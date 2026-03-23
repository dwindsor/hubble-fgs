#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA integration tests for member_info symmetry and persistence.

Validates that both peers reliably retain member_info for each other as long
as adjacency is active. The key regression being tested:

Before fix: UpdatePeerMemberCriterion only refreshed MemberCriteriaMetEpoch when
criteria met-state *changed*. After 30s, checkAdjMbrTimeouts cleared member_info
because the epoch was stale (even though criteria were continuously met).

After fix: The epoch is refreshed on every criterion update where criteria are
met, so each 10-second adjacency tick resets the 30-second timeout window.

Tests:
1. test_ha_member_info_follower_sees_leader  - Follower's peer view of the
   leader contains member_info.lb_mode (this was the asymmetric failing case).
2. test_ha_member_info_leader_sees_follower  - Leader's peer view of the
   follower contains member_info.lb_mode.
3. test_ha_member_info_symmetry             - Both sides see each other's
   lb_mode and the values match the respective device stores.
4. test_ha_member_info_persists_over_time   - member_info is still present on
   both sides after 35+ seconds (beyond the old 30s clearance window).
"""

import time
import pytest
import logging

from helper.command_executor import CommandExecutor
from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, get_peer_member_info, poll_peer_lb_mode,
)

logger = logging.getLogger(__name__)

# How long to soak before re-checking persistence.
# Must exceed the checkAdjMbrTimeouts period (30s) to confirm the fix holds.
MEMBER_INFO_PERSISTENCE_SOAK_SECONDS = 35


# ---------------------------------------------------------------------------
# member_info symmetry tests
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_member_info_follower_sees_leader(
    ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor
):
    """Follower's peer view of the leader contains member_info.lb_mode (45s timeout).

    This is the key asymmetry that was broken before the epoch-refresh fix:
    the leader always saw the follower's member_info, but the follower's view
    of the leader was cleared by checkAdjMbrTimeouts because the epoch became
    stale when criteria stayed continuously met.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    lb_mode = poll_peer_lb_mode(ha_cmd_follower, LEADER_IP, timeout=45)
    assert lb_mode, (
        f"Follower does not see leader member_info.lb_mode within 45s.\n"
        f"Follower HA JSON peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
    )
    logger.info(f"Follower sees leader member_info.lb_mode='{lb_mode}'")


@pytest.mark.ha
def test_ha_member_info_leader_sees_follower(
    ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor
):
    """Leader's peer view of the follower contains member_info.lb_mode (45s timeout)."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    lb_mode = poll_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP, timeout=45)
    assert lb_mode, (
        f"Leader does not see follower member_info.lb_mode within 45s.\n"
        f"Leader HA JSON peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
    )
    logger.info(f"Leader sees follower member_info.lb_mode='{lb_mode}'")


@pytest.mark.ha
def test_ha_member_info_symmetry(
    ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor
):
    """Both peers exchange member_info and the observed lb_mode matches each node's device store.

    Verifies end-to-end symmetry: each side's device store lb_mode equals
    what the other side reports in peer member_info.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    # Give adjacency exchange time to complete on both sides.
    time.sleep(5)

    leader_local_lb = ha_cmd_leader.agw_gnmi_device_show_json().get("lb_mode", "")
    follower_local_lb = ha_cmd_follower.agw_gnmi_device_show_json().get("lb_mode", "")

    assert leader_local_lb, "Leader device store has no lb_mode"
    assert follower_local_lb, "Follower device store has no lb_mode"

    leader_sees_follower = poll_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP, timeout=45)
    follower_sees_leader = poll_peer_lb_mode(ha_cmd_follower, LEADER_IP, timeout=45)

    assert leader_sees_follower == follower_local_lb, (
        f"Leader sees follower lb_mode='{leader_sees_follower}' but follower's device "
        f"store reports '{follower_local_lb}'"
    )
    assert follower_sees_leader == leader_local_lb, (
        f"Follower sees leader lb_mode='{follower_sees_leader}' but leader's device "
        f"store reports '{leader_local_lb}'"
    )
    logger.info(
        f"member_info symmetry confirmed: leader={leader_local_lb}, "
        f"follower={follower_local_lb}"
    )


# ---------------------------------------------------------------------------
# member_info persistence test (regression for epoch-refresh fix)
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_member_info_persists_over_time(
    ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor
):
    """member_info survives beyond the 30-second adjacency member timeout.

    Before the fix, checkAdjMbrTimeouts cleared member_info after 30s because
    MemberCriteriaMetEpoch was only updated when the criteria met-state *changed*
    (not on every update). With steady-state criteria, the epoch went stale and
    member_info was wiped on both sides.

    After the fix, the epoch is refreshed on every met=true update, so the
    30-second window resets each time checkAdjacencies fires (~10s cadence),
    and member_info must remain present indefinitely.

    This test:
    1. Waits for ha-ready on both nodes.
    2. Confirms member_info.lb_mode is present on both sides.
    3. Sleeps for MEMBER_INFO_PERSISTENCE_SOAK_SECONDS (>30s).
    4. Re-checks that member_info.lb_mode is still present — proving the epoch
       is being refreshed and the clearance timeout is not firing.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    # Confirm both sides have member_info before the soak.
    leader_lb_before = poll_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP, timeout=45)
    follower_lb_before = poll_peer_lb_mode(ha_cmd_follower, LEADER_IP, timeout=45)

    assert leader_lb_before, (
        f"Leader does not see follower member_info.lb_mode before soak.\n"
        f"Leader peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
    )
    assert follower_lb_before, (
        f"Follower does not see leader member_info.lb_mode before soak.\n"
        f"Follower peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
    )

    logger.info(
        f"member_info present before soak — "
        f"leader sees follower lb_mode='{leader_lb_before}', "
        f"follower sees leader lb_mode='{follower_lb_before}'. "
        f"Sleeping {MEMBER_INFO_PERSISTENCE_SOAK_SECONDS}s..."
    )

    time.sleep(MEMBER_INFO_PERSISTENCE_SOAK_SECONDS)

    # Re-check after the soak period.
    leader_lb_after = get_peer_member_info(ha_cmd_leader, FOLLOWER_IP).get("lb_mode", "")
    follower_lb_after = get_peer_member_info(ha_cmd_follower, LEADER_IP).get("lb_mode", "")

    assert leader_lb_after, (
        f"Leader's follower member_info.lb_mode was cleared after "
        f"{MEMBER_INFO_PERSISTENCE_SOAK_SECONDS}s soak (expected persistent).\n"
        f"Leader peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
    )
    assert follower_lb_after, (
        f"Follower's leader member_info.lb_mode was cleared after "
        f"{MEMBER_INFO_PERSISTENCE_SOAK_SECONDS}s soak (expected persistent).\n"
        f"Follower peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
    )

    logger.info(
        f"member_info persisted through {MEMBER_INFO_PERSISTENCE_SOAK_SECONDS}s soak — "
        f"leader sees follower='{leader_lb_after}', follower sees leader='{follower_lb_after}'"
    )
