#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA Store & Persistence tests.

Validates that HA store fields are correctly populated after reaching ha-ready.
Follows the nxos store test pattern: one test validates all fields from a
single JSON query with sequential assertions.
"""

import pytest

from helper.ha_helpers import LEADER_IP, FOLLOWER_IP


@pytest.mark.ha
class TestHaStorePopulation:
    """Verify all HA store fields are correctly populated on both nodes."""

    def test_ha_store_population(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both):
        """All HA store fields should be populated after ha-ready.

        ha show JSON structure:
          cluster_state  -> 'ha-ready'
          local.ha_state -> 'ha-ready'
          local.svc_state -> 'ready'
          local.criteria_met -> True
          local.policy_check -> boolean
          local.criteria -> dict with in_service key
          local.flap_count -> int >= 0
          local.recovery_pending -> boolean

        ha info JSON structure:
          admin_state -> 'enabled'
          local_ip -> matches AGW_HA_SOURCE_IP
          ha_port -> > 0
        """
        for name, cmd, expected_ip in [
            ("leader", ha_cmd_leader, LEADER_IP),
            ("follower", ha_cmd_follower, FOLLOWER_IP),
        ]:
            # ha show — cluster and local state
            data = cmd.agw_gnmi_ha_show_json()
            assert data is not None, f"{name}: HA show JSON should not be None"

            assert data.get("cluster_state") == "ha-ready", \
                f"{name}: cluster_state={data.get('cluster_state')}, expected 'ha-ready'"

            local = data.get("local", {})
            assert local.get("ha_state") == "ha-ready", \
                f"{name}: local.ha_state={local.get('ha_state')}, expected 'ha-ready'"
            assert local.get("svc_state") == "ready", \
                f"{name}: local.svc_state={local.get('svc_state')}, expected 'ready'"
            assert local.get("criteria_met") is True, \
                f"{name}: local.criteria_met={local.get('criteria_met')}, expected True"
            assert "policy_check" in local, \
                f"{name}: local.policy_check field missing"
            criteria = local.get("criteria", {})
            assert isinstance(criteria, dict), \
                f"{name}: local.criteria should be a dict, got {type(criteria)}"
            assert "in_service" in criteria, \
                f"{name}: local.criteria missing 'in_service' key"
            assert isinstance(local.get("flap_count"), int), \
                f"{name}: local.flap_count should be int, got {type(local.get('flap_count'))}"
            assert "recovery_pending" in local, \
                f"{name}: local.recovery_pending field missing"

            # ha info — admin state, IP, port
            info = cmd.agw_ha_info_json()
            assert info is not None, f"{name}: HA info JSON should not be None"
            assert info.get("admin_state") == "enabled", \
                f"{name}: admin_state={info.get('admin_state')}, expected 'enabled'"
            assert info.get("local_ip") == expected_ip, \
                f"{name}: local_ip={info.get('local_ip')}, expected {expected_ip}"
            ha_port = info.get("ha_port", 0)
            assert isinstance(ha_port, int) and ha_port > 0, \
                f"{name}: ha_port={ha_port}, expected > 0"

    def test_ha_peer_store_population(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both):
        """All per-peer HA store fields should be populated after ha-ready.

        ha show JSON peer summary structure:
          peers[<ip>].ha_state      -> 'ha-ok'
          peers[<ip>].svc_state     -> 'ready'
          peers[<ip>].membership_ok -> True
          peers[<ip>].adjacency_ok  -> True
          peers[<ip>].service_ok    -> True
        """
        for name, cmd, peer_ip in [
            ("leader", ha_cmd_leader, FOLLOWER_IP),
            ("follower", ha_cmd_follower, LEADER_IP),
        ]:
            data = cmd.agw_gnmi_ha_show_json()
            assert data is not None, f"{name}: HA show JSON should not be None"
            peers = data.get("peers", {})
            assert peer_ip in peers, \
                f"{name}: peer {peer_ip} not found in peers: {list(peers.keys())}"

            peer = peers[peer_ip]
            assert peer.get("ha_state") == "ha-ok", \
                f"{name}: peer ha_state={peer.get('ha_state')}, expected 'ha-ok'"
            assert peer.get("svc_state") == "ready", \
                f"{name}: peer svc_state={peer.get('svc_state')}, expected 'ready'"
            assert peer.get("membership_ok") is True, \
                f"{name}: membership_ok={peer.get('membership_ok')}, expected True"
            assert peer.get("adjacency_ok") is True, \
                f"{name}: adjacency_ok={peer.get('adjacency_ok')}, expected True"
            assert peer.get("service_ok") is True, \
                f"{name}: service_ok={peer.get('service_ok')}, expected True"

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

    def test_ha_leader_election(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both):
        """Leader election: lowest IP address wins.

        HA-states.md Leader Election: lowest IP wins. Leader=172.20.0.2
        (lower) should report is_leader=True, follower=172.20.0.3 should
        report is_leader=False.
        """
        leader_info = ha_cmd_leader.agw_ha_info_json()
        follower_info = ha_cmd_follower.agw_ha_info_json()

        assert leader_info.get("is_leader") is True, \
            f"Leader is_leader={leader_info.get('is_leader')}, expected True (IP {LEADER_IP})"
        assert follower_info.get("is_leader") is False, \
            f"Follower is_leader={follower_info.get('is_leader')}, expected False (IP {FOLLOWER_IP})"

        # Verify IPs are consistent with lowest-wins rule
        assert leader_info.get("local_ip") == LEADER_IP, \
            f"Leader local_ip={leader_info.get('local_ip')}, expected {LEADER_IP}"
        assert follower_info.get("local_ip") == FOLLOWER_IP, \
            f"Follower local_ip={follower_info.get('local_ip')}, expected {FOLLOWER_IP}"

    def test_ha_peer_criteria_populated(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both):
        """All individual peer membership and adjacency criteria should be populated.

        HA-states.md Membership Criteria: peer_compatible, peer_vrf_gid,
        peer_dpu_keepalive. Adjacency Criteria: peer_dpu_bulk_sync,
        peer_policy, peer_ip_config, peer_service.

        Also validates member_info fields (model, sw_version, lb_mode, dpus).
        """
        for name, cmd, peer_ip in [
            ("leader", ha_cmd_leader, FOLLOWER_IP),
            ("follower", ha_cmd_follower, LEADER_IP),
        ]:
            data = cmd.agw_ha_peers_show_json()
            assert data is not None, f"{name}: HA peers show JSON should not be None"

            peers = data.get("peers", {})
            assert peer_ip in peers, \
                f"{name}: peer {peer_ip} not found in peers: {list(peers.keys())}"

            peer = peers[peer_ip]

            # Membership criteria — all must be True at ha-ready
            member_criteria = peer.get("member_criteria", {})
            for criterion in ("peer_compatible", "peer_vrf_gid", "peer_dpu_keepalive"):
                assert member_criteria.get(criterion) is True, \
                    f"{name}: member_criteria.{criterion}={member_criteria.get(criterion)}, expected True"
            assert peer.get("member_criteria_met") is True, \
                f"{name}: member_criteria_met={peer.get('member_criteria_met')}, expected True"

            # Adjacency criteria — all must be True at ha-ready
            adjacency_criteria = peer.get("adjacency_criteria", {})
            for criterion in ("peer_dpu_bulk_sync", "peer_policy", "peer_ip_config", "peer_service"):
                assert adjacency_criteria.get(criterion) is True, \
                    f"{name}: adjacency_criteria.{criterion}={adjacency_criteria.get(criterion)}, expected True"
            assert peer.get("adjacency_criteria_met") is True, \
                f"{name}: adjacency_criteria_met={peer.get('adjacency_criteria_met')}, expected True"

            # Member info should be populated
            member_info = peer.get("member_info", {})
            assert member_info.get("model"), \
                f"{name}: member_info.model should be non-empty"
            assert member_info.get("sw_version"), \
                f"{name}: member_info.sw_version should be non-empty"
            assert member_info.get("lb_mode"), \
                f"{name}: member_info.lb_mode should be non-empty"
            dpus = member_info.get("dpus", [])
            assert len(dpus) > 0, \
                f"{name}: member_info.dpus should have at least one entry"
