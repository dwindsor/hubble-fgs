#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""VRF store subscribe-path tests.

Verifies that gNMI subscribe paths (switch-managed) correctly populate the
VRF store. Agent-managed SET paths (EnforcementBinding, service redirects)
are tested in test_nxos_triggers.py.

All tests run in headless mode (no DPU containers required).
"""

import time

import pytest

from helper.gnmi_paths import (
    create_vrf,
    delete_vrf,
    find_vrf,
    vrf_global_path,
    vrf_service_path,
    vrf_affinity_path,
)


@pytest.mark.nxos
class TestVRFStorePopulation:
    """Verify all subscribe-path fields are populated from mock gNMI seed."""

    def test_vrf_store_population(self, cmd, seed_gnmi):
        """All subscribe-path VRF fields should match mock defaults.

        Subscribe paths tested:
          - VrfStoreGlobalVrfName       -> name, is_global
          - VrfStoreServiceVrfName      -> name, is_service
          - VrfStoreServiceVrfAffinity  -> affinity, is_active
        """
        data = cmd.agw_gnmi_vrf_show_json()
        vrfs = data.get("vrfs", [])

        # All seeded VRFs should be present and active
        seeded_names = {"default", "test-vrf-1", "test-vrf-2"}
        active_vrfs = {v["name"] for v in vrfs if v.get("is_active")}
        for name in seeded_names:
            assert name in active_vrfs, f"Seeded VRF '{name}' should be active"

        # Verify flags on each seeded VRF
        for name in seeded_names:
            vrf = next((v for v in vrfs if v["name"] == name), None)
            assert vrf is not None, f"VRF '{name}' not found"
            assert vrf.get("is_global") is True, f"VRF '{name}' missing global flag"
            assert vrf.get("is_service") is True, f"VRF '{name}' missing service flag"
            assert vrf.get("is_active") is True, f"VRF '{name}' should be active"

        # GID allocation (computed from subscribe-path data)
        default_vrf = next((v for v in vrfs if v["name"] == "default"), None)
        assert default_vrf.get("gid") == 1, (
            f"default VRF GID should be 1, got {default_vrf.get('gid')}"
        )

        gids = []
        for vrf in vrfs:
            if vrf.get("is_active") and vrf.get("gid", 0) > 0:
                gids.append(vrf["gid"])
                if vrf["name"] != "default":
                    assert vrf["gid"] > 1, (
                        f"VRF '{vrf['name']}' GID {vrf['gid']} should be > 1"
                    )
        assert len(gids) == len(set(gids)), f"Duplicate GIDs found: {gids}"


@pytest.mark.nxos
class TestVRFLifecycle:
    """Dynamic VRF creation/deletion via subscribe-path notifications."""

    def test_dynamic_vrf_creation(self, cmd, seed_gnmi):
        """Dynamically created VRF becomes active after global + service + affinity."""
        name = "dynamic-test-vrf"
        try:
            create_vrf(cmd, name)
            cmd.agw_mock_gnmi_set(vrf_affinity_path(name), "0")
            time.sleep(2)

            vrf = find_vrf(cmd, name)
            assert vrf is not None, f"Dynamic VRF '{name}' not found"
            assert vrf.get("is_active"), f"Dynamic VRF '{name}' should be active"
            assert vrf.get("gid", 0) > 0, f"Dynamic VRF '{name}' should have a GID"
        finally:
            delete_vrf(cmd, name)

    def test_dynamic_vrf_deletion(self, cmd, seed_gnmi):
        """Deleted VRF disappears from the store."""
        name = "delete-test-vrf"
        create_vrf(cmd, name)
        cmd.agw_mock_gnmi_set(vrf_affinity_path(name), "0")
        time.sleep(2)

        vrf = find_vrf(cmd, name)
        assert vrf is not None, "VRF should exist before deletion"

        delete_vrf(cmd, name)
        vrf = find_vrf(cmd, name)
        assert vrf is None, "VRF should be removed after deletion"

    def test_vrf_not_active_without_affinity(self, cmd, seed_gnmi):
        """VRF with global + service but no affinity should not be active."""
        name = "no-affinity-vrf"
        try:
            cmd.agw_mock_gnmi_set(vrf_global_path(name), f'"{name}"')
            cmd.agw_mock_gnmi_set(vrf_service_path(name), f'"{name}"')
            time.sleep(2)

            vrf = find_vrf(cmd, name)
            assert vrf is not None, f"VRF '{name}' should exist"
            assert not vrf.get("is_active"), (
                f"VRF '{name}' should NOT be active without affinity"
            )
        finally:
            cmd.agw_mock_gnmi_delete(vrf_global_path(name))
            cmd.agw_mock_gnmi_delete(vrf_service_path(name))
            time.sleep(1)


@pytest.mark.nxos
class TestVRFPinning:
    """DPU pinning derived from ServiceVrfAffinity subscribe path."""

    def test_dynamic_pinning_with_zero_affinity(self, cmd, seed_gnmi):
        """VRF with affinity=0 gets dynamic FNV-1a hash-based pinning."""
        for name in ["test-vrf-1", "test-vrf-2"]:
            vrf = find_vrf(cmd, name)
            assert vrf is not None, f"VRF '{name}' not found"
            assert vrf.get("is_active"), f"VRF '{name}' should be active"
            dpu_pinned = vrf.get("dpu_pinned", 0)
            assert dpu_pinned > 0, (
                f"VRF '{name}' should have a non-zero dpu_pinned"
            )

    def test_static_pinning_with_nonzero_affinity(self, cmd, seed_gnmi):
        """VRF with explicit affinity=1 gets pinned to DPU 1."""
        name = "static-pin-vrf"
        try:
            create_vrf(cmd, name)
            cmd.agw_mock_gnmi_set(vrf_affinity_path(name), "1")
            time.sleep(2)

            vrf = find_vrf(cmd, name)
            assert vrf is not None, f"VRF '{name}' not found"
            assert vrf.get("is_active"), f"VRF '{name}' should be active"
            dpu_pinned = vrf.get("dpu_pinned", 0)
            assert dpu_pinned > 0, (
                f"VRF '{name}' should have a non-zero dpu_pinned"
            )
        finally:
            delete_vrf(cmd, name)

    def test_repinning_on_affinity_change(self, cmd, seed_gnmi):
        """Changing affinity triggers VRF repinning."""
        name = "repin-test-vrf"
        try:
            create_vrf(cmd, name)
            cmd.agw_mock_gnmi_set(vrf_affinity_path(name), "0")
            time.sleep(2)

            vrf_before = find_vrf(cmd, name)
            assert vrf_before is not None and vrf_before.get("is_active")

            cmd.agw_mock_gnmi_set(vrf_affinity_path(name), "2")
            time.sleep(2)

            vrf_after = find_vrf(cmd, name)
            assert vrf_after is not None and vrf_after.get("is_active")
            assert vrf_after.get("dpu_pinned", 0) > 0, (
                "VRF should still have pinning after affinity change"
            )
        finally:
            delete_vrf(cmd, name)
