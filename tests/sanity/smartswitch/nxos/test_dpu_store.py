#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""DPU store subscribe-path tests.

Verifies that gNMI subscribe paths (switch-managed) correctly populate the
DPU store. Agent-managed SET paths (TCPPorts, UDPPorts) and computed port
ranges are tested in test_nxos_triggers.py.

All tests run in headless mode (no DPU containers required).
"""

import time

import pytest

from helper.gnmi_paths import (
    DPU_NUM_DPUS_PATH,
    dpu_ip_path,
    dpu_state_path,
    dpu_version_path,
)


@pytest.mark.nxos
class TestDPUStorePopulation:
    """Verify all subscribe-path fields are populated from mock gNMI seed."""

    def test_dpu_store_population(self, cmd, seed_gnmi):
        """All subscribe-path DPU fields should match mock defaults.

        Subscribe paths tested:
          - DPUStoreNumDPUs    -> expected_count
          - DPUStoreInitState  -> inventory_complete
          - DPUStoreIP         -> dpus[].ip
          - DPUStoreVersion    -> dpus[].version
          - DPUStoreState      -> dpus[].state, dpus[].is_online
        """
        data = cmd.agw_gnmi_dpu_show_json()
        assert data is not None, "DPU show JSON should not be None"

        # NumDPUs subscribe path
        assert data.get("expected_count") == 2, (
            f"expected_count: expected 2, got {data.get('expected_count')}"
        )

        # InitState subscribe path
        assert data.get("inventory_complete") is True, (
            f"inventory_complete: expected True, got {data.get('inventory_complete')}"
        )

        # Computed readiness (depends on subscribe paths)
        assert data.get("is_ready") is True, (
            f"is_ready: expected True, got {data.get('is_ready')}"
        )
        assert data.get("all_online") is True, (
            f"all_online: expected True, got {data.get('all_online')}"
        )

        # Per-DPU subscribe path fields
        dpus = data.get("dpus", [])
        assert len(dpus) >= 2, f"Expected at least 2 DPUs, got {len(dpus)}"

        # Verify seeded DPUs (modules 1 and 2) are present with correct data
        ips = set()
        module_nums = set()
        for dpu in dpus:
            mn = dpu.get("module_num", 0)
            assert mn > 0, f"DPU '{dpu.get('name')}' should have a positive module_num"
            module_nums.add(mn)

            ip = dpu.get("ip", "")
            assert ip != "", f"DPU '{dpu.get('name')}' should have an IP"
            ips.add(ip)

            # DPUStoreState — all seeded DPUs should be online
            assert dpu.get("is_online") is True, (
                f"DPU '{dpu.get('name')}' is_online: expected True"
            )

        # Seeded DPUs must be present
        assert {1, 2}.issubset(module_nums), (
            f"Expected module_nums to include {{1, 2}}, got {module_nums}"
        )
        assert {"192.168.1.1", "192.168.1.2"}.issubset(ips), (
            f"Expected IPs to include {{192.168.1.1, 192.168.1.2}}, got {ips}"
        )


@pytest.mark.nxos
class TestDPUDynamicDiscovery:
    """Dynamic DPU discovery via gNMI subscribe-path notifications."""

    def test_add_dpu_via_gnmi(self, cmd, seed_gnmi):
        """Adding a new DPU via gNMI notifications populates the store."""
        new_module = 10
        new_ip = "192.168.10.10"

        try:
            # Set DPU fields for a new module (idempotent if it already exists)
            cmd.agw_mock_gnmi_set(DPU_NUM_DPUS_PATH, "10")
            cmd.agw_mock_gnmi_set(dpu_ip_path(new_module), f'"{new_ip}"')
            cmd.agw_mock_gnmi_set(dpu_state_path(new_module), '"online"')
            cmd.agw_mock_gnmi_set(dpu_version_path(new_module), '"2.0.0"')
            time.sleep(2)

            data_after = cmd.agw_gnmi_dpu_show_json()

            # Verify the DPU is present with correct data
            new_dpu = next(
                (d for d in data_after.get("dpus", []) if d.get("module_num") == new_module),
                None,
            )
            assert new_dpu is not None, f"DPU module {new_module} should exist"
            assert new_dpu.get("ip") == new_ip, (
                f"Expected ip='{new_ip}', got '{new_dpu.get('ip')}'"
            )
            assert new_dpu.get("version") == "2.0.0"
            assert new_dpu.get("is_online") is True
        finally:
            # Restore original expected count
            cmd.agw_mock_gnmi_set(DPU_NUM_DPUS_PATH, "2")
            time.sleep(1)

    def test_dpu_state_change_via_gnmi(self, cmd, seed_gnmi):
        """Changing DPU state via gNMI should update the store."""
        try:
            cmd.agw_mock_gnmi_set(dpu_state_path(1), '"failed"')
            time.sleep(2)

            data = cmd.agw_gnmi_dpu_show_json()
            dpus = data.get("dpus", [])
            dpu1 = next((d for d in dpus if d.get("module_num") == 1), None)
            assert dpu1 is not None, "DPU-1 should still exist"
            assert dpu1.get("is_online") is not True, (
                "DPU-1 should NOT be online after state change to failed"
            )
            assert dpu1.get("state") == "failed", (
                f"DPU-1 state: expected 'failed', got '{dpu1.get('state')}'"
            )
        finally:
            cmd.agw_mock_gnmi_set(dpu_state_path(1), '"online"')
            time.sleep(1)
