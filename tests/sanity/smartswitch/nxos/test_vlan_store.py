#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""VLAN store subscribe-path tests.

Verifies that gNMI subscribe paths (switch-managed) correctly populate the
VLAN store. Agent-managed SET paths (EnforcementBinding, service redirects)
are tested in test_nxos_triggers.py.

All tests run in headless mode (no DPU containers required).
"""

import time

import pytest

from helper.gnmi_paths import (
    create_vlan,
    delete_vlan,
    find_vlan,
    vlan_global_path,
    vlan_service_path,
    vlan_affinity_path,
)


@pytest.mark.nxos
class TestVLANStorePopulation:
    """Verify all subscribe-path fields are populated from mock gNMI seed."""

    def test_vlan_store_population(self, cmd, seed_gnmi):
        """All subscribe-path VLAN fields should match mock defaults.

        Subscribe paths tested:
          - VlanStoreGlobalVlanName       -> name, is_global
          - VlanStoreServiceVlanName      -> name, is_service
          - VlanStoreServiceVlanAffinity  -> affinity, is_active
        """
        data = cmd.agw_gnmi_vlan_show_json()
        vlans = data.get("vlans") or []

        # Should have at least the seeded VLANs
        assert len(vlans) >= 2, f"Expected at least 2 VLANs, got {len(vlans)}"

        # Seeded VLANs should be active
        seeded_names = {"vxlan-100", "vxlan-200"}
        active_vlans = {v["name"] for v in vlans if v.get("is_active")}
        for name in seeded_names:
            assert name in active_vlans, f"Seeded VLAN '{name}' should be active"

        # Verify flags on each seeded VLAN
        for name in seeded_names:
            vlan = next((v for v in vlans if v["name"] == name), None)
            assert vlan is not None, f"VLAN '{name}' not found"
            assert vlan.get("is_global") is True, f"VLAN '{name}' missing global flag"
            assert vlan.get("is_service") is True, f"VLAN '{name}' missing service flag"
            assert vlan.get("is_active") is True, f"VLAN '{name}' should be active"
            assert vlan.get("dpu_pinned", 0) > 0, (
                f"VLAN '{name}' should have a non-zero dpu_pinned"
            )


@pytest.mark.nxos
class TestVLANLifecycle:
    """Dynamic VLAN creation/deletion via subscribe-path notifications."""

    def test_dynamic_vlan_creation(self, cmd, seed_gnmi):
        """Dynamically created VLAN becomes active after global + service + affinity."""
        vid = "vxlan-300"
        try:
            create_vlan(cmd, vid)
            cmd.agw_mock_gnmi_set(vlan_affinity_path(vid), "0")
            time.sleep(2)

            vlan = find_vlan(cmd, vid)
            assert vlan is not None, f"Dynamic VLAN '{vid}' not found"
            assert vlan.get("is_active"), f"Dynamic VLAN '{vid}' should be active"
        finally:
            delete_vlan(cmd, vid)

    def test_dynamic_vlan_deletion(self, cmd, seed_gnmi):
        """Deleted VLAN disappears from the store."""
        vid = "vxlan-400"
        create_vlan(cmd, vid)
        cmd.agw_mock_gnmi_set(vlan_affinity_path(vid), "0")
        time.sleep(2)

        vlan = find_vlan(cmd, vid)
        assert vlan is not None, "VLAN should exist before deletion"

        delete_vlan(cmd, vid)
        vlan = find_vlan(cmd, vid)
        assert vlan is None, "VLAN should be removed after deletion"

    def test_vlan_not_active_without_affinity(self, cmd, seed_gnmi):
        """VLAN with global + service but no affinity should not be active."""
        vid = "vxlan-500"
        try:
            cmd.agw_mock_gnmi_set(vlan_global_path(vid), f'"{vid}"')
            cmd.agw_mock_gnmi_set(vlan_service_path(vid), f'"{vid}"')
            time.sleep(2)

            vlan = find_vlan(cmd, vid)
            assert vlan is not None, f"VLAN '{vid}' should exist"
            assert not vlan.get("is_active"), (
                f"VLAN '{vid}' should NOT be active without affinity"
            )
        finally:
            cmd.agw_mock_gnmi_delete(vlan_global_path(vid))
            cmd.agw_mock_gnmi_delete(vlan_service_path(vid))
            time.sleep(1)


@pytest.mark.nxos
class TestVLANPinning:
    """DPU pinning derived from ServiceVlanAffinity subscribe path."""

    def test_dynamic_pinning_with_zero_affinity(self, cmd, seed_gnmi):
        """VLAN with affinity=0 gets dynamic pinning."""
        for name in ["vxlan-100", "vxlan-200"]:
            vlan = find_vlan(cmd, name)
            assert vlan is not None, f"VLAN '{name}' not found"
            assert vlan.get("is_active"), f"VLAN '{name}' should be active"
            dpu_pinned = vlan.get("dpu_pinned", 0)
            assert dpu_pinned > 0, (
                f"VLAN '{name}' should have a non-zero dpu_pinned"
            )

    def test_static_pinning_with_nonzero_affinity(self, cmd, seed_gnmi):
        """VLAN with explicit affinity=1 gets pinned."""
        vid = "vxlan-800"
        try:
            create_vlan(cmd, vid)
            cmd.agw_mock_gnmi_set(vlan_affinity_path(vid), "1")
            time.sleep(2)

            vlan = find_vlan(cmd, vid)
            assert vlan is not None, f"VLAN '{vid}' not found"
            assert vlan.get("is_active"), f"VLAN '{vid}' should be active"
            dpu_pinned = vlan.get("dpu_pinned", 0)
            assert dpu_pinned > 0, (
                f"VLAN '{vid}' should have a non-zero dpu_pinned"
            )
        finally:
            delete_vlan(cmd, vid)

    def test_repinning_on_affinity_change(self, cmd, seed_gnmi):
        """Changing affinity triggers VLAN repinning."""
        vid = "vxlan-900"
        try:
            create_vlan(cmd, vid)
            cmd.agw_mock_gnmi_set(vlan_affinity_path(vid), "0")
            time.sleep(2)

            vlan_before = find_vlan(cmd, vid)
            assert vlan_before is not None and vlan_before.get("is_active")

            cmd.agw_mock_gnmi_set(vlan_affinity_path(vid), "2")
            time.sleep(2)

            vlan_after = find_vlan(cmd, vid)
            assert vlan_after is not None and vlan_after.get("is_active")
            assert vlan_after.get("dpu_pinned", 0) > 0, (
                "VLAN should still have pinning after affinity change"
            )
        finally:
            delete_vlan(cmd, vid)
