#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA Membership Failure tests.

Membership criteria failures cause ha-fail -> active/standby.

State Table row (HA-states.md):
  ready / not-ready / ha-fail -> active/standby

Recovery path (HA-states.md "Recovery From Failover"):
  ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)

Membership criteria (HA-states.md):
  NXOS Version, AGW Version, DPU Version, Model, DPU Count, Policy Check,
  LB Mode, VRF/VLAN Reconciliation, VRF/VLAN Pinning, DPU Keepalive
"""

import time

import pytest

from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, poll_ha_state, poll_peer_membership_ok,
    get_local_ha_state, assert_no_state_flapping,
    assert_state_transition_order,
)
from helper.gnmi_paths import LB_MODE_PATH, DPU_NUM_DPUS_PATH


@pytest.mark.ha
@pytest.mark.timeout(240)
class TestMembershipFailure:

    def test_membership_peer_fail(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Debug membership failure triggers ha-fail -> active/standby.

        State Table: ready / not-ready / ha-fail -> active/standby
        MO Translation: ha-takeover (active), ha-switchover (standby)
        """
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, membership=True)
        time.sleep(5)

        data = ha_cmd_leader.agw_gnmi_ha_show_json()
        peer = data.get("peers", {}).get(FOLLOWER_IP, {})
        assert peer.get("membership_ok") is False, \
            f"Peer membership_ok={peer.get('membership_ok')}, expected False"

        # Leader (active) should transition to ha-takeover
        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=30), \
            f"Leader ha_state={get_local_ha_state(ha_cmd_leader).get('ha_state')}, expected ha-takeover"

        # Follower (standby) should transition to ha-switchover
        assert poll_ha_state(ha_cmd_follower, "ha-switchover", timeout=30), \
            f"Follower ha_state={get_local_ha_state(ha_cmd_follower).get('ha_state')}, expected ha-switchover"

    def test_membership_peer_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Recovery from membership failure follows standby path.

        Recovery: ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, membership=True)
        time.sleep(5)

        ha_cmd_leader.agw_ha_debug_peer_ok(FOLLOWER_IP, membership=True)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after membership peer ok"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") == "ha-ready", \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-ready"

    def test_membership_lb_mode_mismatch(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """LB mode mismatch causes membership failure -> ha-fail, active/standby.

        State Table: ready / not-ready / ha-fail -> active/standby
        MO Translation: ha-takeover (active), ha-switchover (standby)
        """
        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, '"dpu_pinning"')
        time.sleep(5)

        assert poll_peer_membership_ok(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=45), \
            "Leader did not detect membership_ok=False after LB mode mismatch"

        data = ha_cmd_leader.agw_gnmi_ha_show_json()
        peer = data.get("peers", {}).get(FOLLOWER_IP, {})
        assert peer.get("membership_ok") is False, \
            f"Peer membership_ok={peer.get('membership_ok')}, expected False"

        # Leader (active) should transition to ha-takeover
        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=30), \
            f"Leader ha_state={get_local_ha_state(ha_cmd_leader).get('ha_state')}, expected ha-takeover"

    def test_membership_lb_mode_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Restoring LB mode recovers through standby path.

        Recovery: ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, '"dpu_pinning"')
        assert poll_peer_membership_ok(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=45), \
            "Mismatch not detected"

        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, '"symmetric_hash"')

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after LB mode restore"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready"

    def test_membership_dpu_count_mismatch(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """DPU count mismatch causes membership failure -> ha-fail, active/standby.

        HA-states.md Membership Criteria: DPU Count must match exactly.
        Changing numDpus on leader creates a mismatch with follower.
        """
        ha_cmd_leader.agw_mock_gnmi_set(DPU_NUM_DPUS_PATH, '"4"')
        time.sleep(5)

        assert poll_peer_membership_ok(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=45), \
            "Leader did not detect membership_ok=False after DPU count mismatch"

        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=30), \
            f"Leader ha_state={get_local_ha_state(ha_cmd_leader).get('ha_state')}, expected ha-takeover"

    def test_membership_dpu_count_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Restoring DPU count recovers through standby path.

        Recovery: ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        ha_cmd_leader.agw_mock_gnmi_set(DPU_NUM_DPUS_PATH, '"4"')
        assert poll_peer_membership_ok(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=45), \
            "Mismatch not detected"

        ha_cmd_leader.agw_mock_gnmi_set(DPU_NUM_DPUS_PATH, '"2"')

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after DPU count restore"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready"

    def test_membership_gnmi_write_order(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """gNMI writes during membership failure/recovery should not flap.

        Expected agentHaState sequence: ha-ready -> ha-takeover -> ha-ready
        (intermediate states like ha-not-ready during standby removal are
        filtered by assert_state_transition_order)
        """
        ha_cmd_leader.agw_ha_debug_peer_fail(FOLLOWER_IP, membership=True)
        time.sleep(5)
        ha_cmd_leader.agw_ha_debug_peer_ok(FOLLOWER_IP, membership=True)
        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover"

        assert_no_state_flapping(ha_cmd_leader)
        assert_state_transition_order(
            ha_cmd_leader,
            ["ha-ready", "ha-takeover", "ha-ready"],
        )
