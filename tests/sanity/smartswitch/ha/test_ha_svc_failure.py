#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA Service Failure tests.

ha debug fail is a critical service failure -> ha-unavailable (not ha-fail).

State Table rows (HA-states.md):
  - ready / not-ready / ha-unavailable -> standalone (healthy peer)
  - not-ready / ready / ha-unavailable -> unavailable (failed node)
  - not-ready / not-ready / ha-unavailable -> unavailable (both)

Recovery path (HA-states.md "Recovery From Failover"):
  unavailable -> ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
"""

import time

import pytest

from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, get_local_ha_state, poll_ha_state,
    poll_peer_service_ok,
    assert_no_state_flapping, assert_state_transition_order,
)


@pytest.mark.ha
@pytest.mark.timeout(240)
class TestSvcFailure:

    def test_svc_local_fail(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Local service failure via ha debug fail.

        State Table: not-ready / ready / ha-unavailable -> unavailable (leader)
        State Table: ready / not-ready / ha-unavailable -> standalone (follower)
        """
        ha_cmd_leader.agw_ha_debug_fail()
        time.sleep(5)

        # Leader should be unavailable (local svc failure)
        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("svc_state") == "not-ready", \
            f"Leader svc_state={leader.get('svc_state')}, expected 'not-ready'"
        assert leader.get("ha_state") in ("ha-unavailable", "unavailable"), \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-unavailable"

        # Follower should be standalone (peer svc failure)
        follower = get_local_ha_state(ha_cmd_follower)
        assert follower.get("ha_state") in ("ha-not-ready", "standalone"), \
            f"Follower ha_state={follower.get('ha_state')}, expected standalone/ha-not-ready"

        # Follower's view of leader should show service_ok=False
        assert poll_peer_service_ok(ha_cmd_follower, LEADER_IP, expected=False, timeout=30), \
            "Follower did not detect service_ok=False for leader after debug fail"

    def test_svc_local_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Recovery from local service failure follows standby path.

        Recovery path: ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        ha_cmd_leader.agw_ha_debug_fail()
        time.sleep(5)

        ha_cmd_leader.agw_ha_debug_ok()

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after debug ok"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready after leader recovery"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") == "ha-ready", \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-ready"
        assert leader.get("svc_state") == "ready", \
            f"Leader svc_state={leader.get('svc_state')}, expected ready"

    def test_svc_peer_fail(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Peer service failure via ha debug fail on follower.

        State Table: ready / not-ready / ha-unavailable -> standalone (leader)
        State Table: not-ready / ready / ha-unavailable -> unavailable (follower)
        """
        ha_cmd_follower.agw_ha_debug_fail()
        time.sleep(5)

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-not-ready", "standalone"), \
            f"Leader ha_state={leader.get('ha_state')}, expected standalone/ha-not-ready"

        follower = get_local_ha_state(ha_cmd_follower)
        assert follower.get("svc_state") == "not-ready", \
            f"Follower svc_state={follower.get('svc_state')}, expected not-ready"
        assert follower.get("ha_state") in ("ha-unavailable", "unavailable"), \
            f"Follower ha_state={follower.get('ha_state')}, expected ha-unavailable"

        # Leader's view of follower should show service_ok=False
        assert poll_peer_service_ok(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=30), \
            "Leader did not detect service_ok=False for follower after debug fail"

    def test_svc_both_fail(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Both nodes service failure.

        State Table: not-ready / not-ready / ha-unavailable -> unavailable (both)
        """
        ha_cmd_leader.agw_ha_debug_fail()
        ha_cmd_follower.agw_ha_debug_fail()
        time.sleep(5)

        for name, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
            local = get_local_ha_state(cmd)
            assert local.get("svc_state") == "not-ready", \
                f"{name}: svc_state={local.get('svc_state')}, expected not-ready"
            assert local.get("ha_state") in ("ha-unavailable", "unavailable"), \
                f"{name}: ha_state={local.get('ha_state')}, expected ha-unavailable/unavailable"

    def test_svc_recovery_peer_enters_switchover(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Recovering peer enters ha-switchover before ha-ready during takeover.

        HA-states.md State Recovery (lines 302-324):
          1. Leader enters ha-takeover via membership failure
          2. Follower enters ha-switchover (does not pull traffic)
          3. After membership re-established, both transition to ha-ready

        Verifies follower's gNMI write sequence includes ha-switchover.
        """
        # Trigger membership failure so leader enters ha-takeover
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, membership=True)
        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=30), \
            f"Leader ha_state={get_local_ha_state(ha_cmd_leader).get('ha_state')}, expected ha-takeover"
        assert poll_ha_state(ha_cmd_follower, "ha-switchover", timeout=30), \
            f"Follower ha_state={get_local_ha_state(ha_cmd_follower).get('ha_state')}, expected ha-switchover"

        # Recover — clear membership failure
        ha_cmd_leader.agw_ha_debug_peer_ok(FOLLOWER_IP, membership=True)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready"

        # Verify follower went through ha-switchover on its way to ha-ready
        assert_state_transition_order(
            ha_cmd_follower,
            ["ha-ready", "ha-switchover", "ha-ready"],
        )

    def test_svc_gnmi_write_order(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """gNMI state writes should follow expected MO-translated sequence.

        Expected agentHaState sequence (HA-states.md MO Translation):
          ha-ready -> ha-unavailable -> ha-switchover -> ha-ready

        Service failure -> ha-unavailable (unavailable). Recovery goes through
        active/standby (syncing) where recovering node is standby ->
        ha-switchover, then active/active -> ha-ready.
        """
        ha_cmd_leader.agw_ha_debug_fail()
        time.sleep(5)

        ha_cmd_leader.agw_ha_debug_ok()
        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready"

        assert_no_state_flapping(ha_cmd_leader)
        assert_state_transition_order(
            ha_cmd_leader,
            ["ha-ready", "ha-unavailable", "ha-switchover", "ha-ready"],
        )
