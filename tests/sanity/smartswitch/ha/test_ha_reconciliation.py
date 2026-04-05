#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA VRF GID Reconciliation tests.

Validates that VRF GID reconciliation works correctly when two HA nodes
connect with colliding GID assignments. Tests cover:
  - Baseline GID consistency (moved from test_ha_store.py)
  - Collision resolution when VRFs are created in different order on each node
"""

import time
import logging

import pytest

from helper.ha_helpers import LEADER_IP, FOLLOWER_IP, wait_for_ha_ready
from helper.gnmi_paths import (
    HA_ADMIN_STATE_PATH,
    HA_IP_PATH,
    HA_SWITCH_STATE_PATH,
    create_vrf,
    delete_vrf,
    ha_peer_ip_path,
    ha_peer_ip_config_state_path,
    vrf_affinity_path,
    vrf_service_endpoint_path,
    vrf_enforcement_path,
    vrf_pmap_path,
)

logger = logging.getLogger(__name__)


def _get_vrf_by_name(cmd):
    """Return a dict mapping VRF name -> VRF entry from vrf show JSON."""
    data = cmd.agw_gnmi_vrf_show_json()
    return {v["name"]: v for v in data.get("vrfs", [])}


def _remove_peers(cmd):
    """Remove all HA peers on a node and wait for the peer list to empty.

    Deletes each peer individually via its per-peer gNMI path so that
    ExtractHAPeerIP can parse the [ipAddr=X] key and trigger RemovePeer.
    """
    # First, discover current peer IPs
    try:
        data = cmd.agw_gnmi_ha_show_json()
        peer_ips = list(data.get("peers", {}).keys())
    except Exception:
        peer_ips = []

    if not peer_ips:
        return True

    for ip in peer_ips:
        cmd.agw_mock_gnmi_delete(ha_peer_ip_path(ip))

    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            data = cmd.agw_gnmi_ha_show_json()
            peers = data.get("peers", {})
            if not peers:
                return True
        except Exception:
            pass
        time.sleep(2)
    logger.warning("HA peers did not clear within 30s")
    return False


def _add_peer(cmd, ha_ip, peer_ip):
    """Add a peer to a node by setting per-peer gNMI leaf paths."""
    cmd.agw_mock_gnmi_set(HA_IP_PATH, f'"{ha_ip}"')
    cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"enabled"')
    cmd.agw_mock_gnmi_set(HA_SWITCH_STATE_PATH, '"ha-ready"')
    cmd.agw_mock_gnmi_set(ha_peer_ip_path(peer_ip), f'"{peer_ip}"')
    cmd.agw_mock_gnmi_set(ha_peer_ip_config_state_path(peer_ip), '"success"')


@pytest.mark.ha
@pytest.mark.timeout(300)
class TestVrfGidReconciliation:
    """VRF GID reconciliation tests between HA peers."""

    def test_ha_vrf_gid_reconciliation(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both):
        """VRF GIDs should be reconciled between peers after ha-ready.

        Validates:
          - GIDs match on both nodes for same VRF names
          - preset == gid for each VRF (reconciliation complete)
          - No duplicate GIDs on either node
          - Static GIDs (from AGW_VRF_MAP) are preserved
        """
        leader_vrfs = ha_cmd_leader.agw_gnmi_vrf_show_json()
        follower_vrfs = ha_cmd_follower.agw_gnmi_vrf_show_json()

        leader_list = leader_vrfs.get("vrfs", [])
        follower_list = follower_vrfs.get("vrfs", [])
        assert leader_list, "Leader VRF list should not be empty"
        assert follower_list, "Follower VRF list should not be empty"

        leader_by_name = {v["name"]: v for v in leader_list}
        follower_by_name = {v["name"]: v for v in follower_list}

        # GIDs match on both nodes
        common_names = set(leader_by_name.keys()) & set(follower_by_name.keys())
        assert common_names, "No common VRF names between leader and follower"
        for name in common_names:
            l_gid = leader_by_name[name].get("gid", 0)
            f_gid = follower_by_name[name].get("gid", 0)
            assert l_gid == f_gid, \
                f"VRF '{name}' GID mismatch: leader={l_gid}, follower={f_gid}"

        # preset == gid (reconciliation complete)
        for vrf in leader_list:
            gid = vrf.get("gid", 0)
            preset = vrf.get("preset", 0)
            if gid > 0:
                assert preset == gid, \
                    f"VRF '{vrf['name']}' preset={preset} != gid={gid}"

        # No duplicate GIDs
        for label, vrf_list in [("leader", leader_list), ("follower", follower_list)]:
            gids = [v.get("gid", 0) for v in vrf_list if v.get("gid", 0) > 0]
            assert len(gids) == len(set(gids)), \
                f"{label}: duplicate GIDs found: {gids}"

        # Static GIDs preserved (default:1 from AGW_VRF_MAP)
        if "default" in leader_by_name:
            assert leader_by_name["default"].get("gid") == 1, \
                "Static GID for 'default' VRF should be 1"

    def test_colliding_vrf_gids_reconcile(
        self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class
    ):
        """VRF GID collisions should be resolved when HA peers connect.

        Setup:
          - Leader creates VRFs: tenant1, tenant2, tenant3, tenant4
          - Follower creates VRFs: tenant1, tenant3, tenant2, tenant4
          - tenant2 and tenant3 get swapped GIDs between nodes

        After HA is enabled, reconciliation should:
          - Assign matching GIDs across both nodes for all VRFs
          - Complete reconciliation (preset == gid)
          - Preserve static GIDs (default:1)
          - Program VRF redirects on the leader
        """
        tenant_vrfs = ["tenant1", "tenant2", "tenant3", "tenant4"]
        leader_order = ["tenant1", "tenant2", "tenant3", "tenant4"]
        follower_order = ["tenant1", "tenant3", "tenant2", "tenant4"]

        # --- Phase 1: Remove peers to disconnect nodes ---
        logger.info("Removing peers on both nodes to disconnect HA")
        assert _remove_peers(ha_cmd_leader), "Leader peers did not clear"
        assert _remove_peers(ha_cmd_follower), "Follower peers did not clear"
        time.sleep(3)

        # --- Phase 2: Clean up existing VRFs and create tenants ---
        logger.info("Deleting seeded and tenant VRFs on both nodes")
        for cmd in (ha_cmd_leader, ha_cmd_follower):
            for vrf_name in ("test-vrf-1", "test-vrf-2") + tuple(tenant_vrfs):
                try:
                    delete_vrf(cmd, vrf_name)
                except Exception:
                    pass

        logger.info("Creating tenant VRFs on leader: %s", leader_order)
        for name in leader_order:
            create_vrf(ha_cmd_leader, name)
            ha_cmd_leader.agw_mock_gnmi_set(vrf_affinity_path(name), '"0"')
            time.sleep(2)

        logger.info("Creating tenant VRFs on follower: %s", follower_order)
        for name in follower_order:
            create_vrf(ha_cmd_follower, name)
            ha_cmd_follower.agw_mock_gnmi_set(vrf_affinity_path(name), '"0"')
            time.sleep(2)

        # --- Phase 3: Verify GID collision exists ---
        leader_by_name = _get_vrf_by_name(ha_cmd_leader)
        follower_by_name = _get_vrf_by_name(ha_cmd_follower)

        l_t2_gid = leader_by_name.get("tenant2", {}).get("gid", 0)
        l_t3_gid = leader_by_name.get("tenant3", {}).get("gid", 0)
        f_t2_gid = follower_by_name.get("tenant2", {}).get("gid", 0)
        f_t3_gid = follower_by_name.get("tenant3", {}).get("gid", 0)

        logger.info(
            "Pre-HA GIDs — leader: tenant2=%d tenant3=%d, follower: tenant2=%d tenant3=%d",
            l_t2_gid, l_t3_gid, f_t2_gid, f_t3_gid,
        )
        assert l_t2_gid != f_t2_gid or l_t3_gid != f_t3_gid, (
            "Expected GID collision between tenant2/tenant3 but GIDs already match: "
            f"leader=({l_t2_gid},{l_t3_gid}), follower=({f_t2_gid},{f_t3_gid})"
        )

        # --- Phase 4: Re-add peers to reconnect HA ---
        logger.info("Re-adding peers on both nodes to trigger reconnection")
        _add_peer(ha_cmd_leader, LEADER_IP, FOLLOWER_IP)
        _add_peer(ha_cmd_follower, FOLLOWER_IP, LEADER_IP)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=90), \
            "Leader did not reach ha-ready after enabling HA"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=90), \
            "Follower did not reach ha-ready after enabling HA"

        # --- Phase 5: Wait for membership on both nodes ---
        for name, cmd, peer_ip in [
            ("leader", ha_cmd_leader, FOLLOWER_IP),
            ("follower", ha_cmd_follower, LEADER_IP),
        ]:
            deadline = time.time() + 60
            membership_ok = False
            while time.time() < deadline:
                data = cmd.agw_gnmi_ha_show_json()
                peer = data.get("peers", {}).get(peer_ip, {})
                if peer.get("membership_ok") is True:
                    membership_ok = True
                    break
                time.sleep(3)
            assert membership_ok, \
                f"{name}: membership_ok did not become True within 60s"

        # --- Phase 6: Verify GID reconciliation ---
        leader_by_name = _get_vrf_by_name(ha_cmd_leader)
        follower_by_name = _get_vrf_by_name(ha_cmd_follower)

        # All tenant VRFs should exist on both nodes
        for vrf_name in tenant_vrfs:
            assert vrf_name in leader_by_name, \
                f"VRF '{vrf_name}' missing from leader after reconciliation"
            assert vrf_name in follower_by_name, \
                f"VRF '{vrf_name}' missing from follower after reconciliation"

        # GIDs must match across nodes
        for vrf_name in tenant_vrfs:
            l_gid = leader_by_name[vrf_name].get("gid", 0)
            f_gid = follower_by_name[vrf_name].get("gid", 0)
            assert l_gid == f_gid, \
                f"VRF '{vrf_name}' GID mismatch after reconciliation: leader={l_gid}, follower={f_gid}"
            assert l_gid > 0, \
                f"VRF '{vrf_name}' has zero GID after reconciliation"

        # preset == gid (reconciliation complete)
        for label, by_name in [("leader", leader_by_name), ("follower", follower_by_name)]:
            for vrf_name in tenant_vrfs:
                vrf = by_name[vrf_name]
                gid = vrf.get("gid", 0)
                preset = vrf.get("preset", 0)
                assert preset == gid, \
                    f"{label}: VRF '{vrf_name}' preset={preset} != gid={gid}"

        # No duplicate GIDs on either node
        for label, by_name in [("leader", leader_by_name), ("follower", follower_by_name)]:
            gids = [v.get("gid", 0) for v in by_name.values() if v.get("gid", 0) > 0]
            assert len(gids) == len(set(gids)), \
                f"{label}: duplicate GIDs found: {gids}"

        # Static GID preserved
        if "default" in leader_by_name:
            assert leader_by_name["default"].get("gid") == 1, \
                "Static GID for 'default' VRF should be 1"

        # --- Phase 7: Verify VRF redirects programmed on leader ---
        for vrf_name in tenant_vrfs:
            svc = ha_cmd_leader.agw_mock_gnmi_get(vrf_service_endpoint_path(vrf_name))
            assert svc, \
                f"VRF '{vrf_name}' service endpoint redirect not programmed on leader"

            enf = ha_cmd_leader.agw_mock_gnmi_get(vrf_enforcement_path(vrf_name))
            assert enf, \
                f"VRF '{vrf_name}' enforcement binding not programmed on leader"

            pmap = ha_cmd_leader.agw_mock_gnmi_get(vrf_pmap_path(vrf_name))
            assert pmap, \
                f"VRF '{vrf_name}' policy map not programmed on leader"
