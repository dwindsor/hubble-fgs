#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA Adjacency Failure tests.

Adjacency criteria failures cause ha-degraded, both peers remain active/active.

State Table row (HA-states.md):
  ready / ready / ha-degraded -> active/active

Adjacency criteria (HA-states.md): Bulk Sync, Inline Sync, Policy Revision
"""

import time

import pytest

from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, poll_ha_state, get_local_ha_state,
    assert_no_state_flapping, assert_state_transition_order,
)


@pytest.mark.ha
@pytest.mark.timeout(180)
class TestAdjacencyFailure:

    def test_adjacency_peer_fail(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Debug adjacency failure triggers ha-degraded, both still active/active.

        State Table: ready / ready / ha-degraded -> active/active
        """
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, adjacency=True)
        time.sleep(5)

        assert poll_ha_state(ha_cmd_leader, "ha-degraded", timeout=30), \
            "Leader did not reach ha-degraded after adjacency peer fail"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("svc_state") == "ready", \
            f"Leader svc_state={leader.get('svc_state')}, expected ready"

        follower = get_local_ha_state(ha_cmd_follower)
        assert follower.get("svc_state") == "ready", \
            f"Follower svc_state={follower.get('svc_state')}, expected ready"

        # Both peers should report ha-degraded (active/active with adjacency issue)
        assert poll_ha_state(ha_cmd_follower, "ha-degraded", timeout=30), \
            f"Follower ha_state={get_local_ha_state(ha_cmd_follower).get('ha_state')}, expected ha-degraded"

        data = ha_cmd_leader.agw_gnmi_ha_show_json()
        peer = data.get("peers", {}).get(FOLLOWER_IP, {})
        assert peer.get("adjacency_ok") is False, \
            f"Peer adjacency_ok={peer.get('adjacency_ok')}, expected False"

    def test_adjacency_peer_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Recovery from adjacency failure restores ha-ok, active/active."""
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, adjacency=True)
        assert poll_ha_state(ha_cmd_leader, "ha-degraded", timeout=30), \
            "Leader did not reach ha-degraded"

        ha_cmd_leader.agw_ha_debug_peer_ok(FOLLOWER_IP, adjacency=True)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after adjacency peer ok"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") == "ha-ready", \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-ready"

        data = ha_cmd_leader.agw_gnmi_ha_show_json()
        peer = data.get("peers", {}).get(FOLLOWER_IP, {})
        assert peer.get("adjacency_ok") is True, \
            f"Peer adjacency_ok={peer.get('adjacency_ok')}, expected True"

    def test_adjacency_gnmi_write_order(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """gNMI writes during adjacency failure/recovery should not flap.

        Expected agentHaState sequence: ha-ready -> ha-degraded -> ha-ready
        """
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, adjacency=True)
        assert poll_ha_state(ha_cmd_leader, "ha-degraded", timeout=30), \
            "Leader did not reach ha-degraded"

        ha_cmd_leader.agw_ha_debug_peer_ok(FOLLOWER_IP, adjacency=True)
        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover"

        assert_no_state_flapping(ha_cmd_leader)
        assert_state_transition_order(
            ha_cmd_leader,
            ["ha-ready", "ha-degraded", "ha-ready"],
        )
