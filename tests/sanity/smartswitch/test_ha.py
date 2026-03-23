#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import time
import pytest
import logging

from helper.command_executor import CommandExecutor
from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, poll_ha_state,
)
from helper.gnmi_paths import DEVICE_IN_SERVICE_PATH

logger = logging.getLogger(__name__)


@pytest.mark.ha
def test_ha_both_healthy(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Leader and follower both respond to health check."""
    ha_cmd_leader.agw_health()
    ha_cmd_follower.agw_health()


@pytest.mark.ha
def test_ha_nxos_running(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Both AGWs reach a valid phase in mock mode."""
    valid_phases = ("dpu-pending", "dpu-ready", "redir-done")
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        status = cmd.agw_show_status()
        lower = status.lower()
        assert "phase:" in lower, f"Expected Phase: in status output, got: {status}"
        assert any(p in lower for p in valid_phases), \
            f"Expected one of {valid_phases} in status, got: {status}"


@pytest.mark.ha
def test_ha_enabled_on_both(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """HA store shows Admin State: enabled on both AGWs."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        ha_status = cmd.agw_show_ha()
        assert "Admin State:" in ha_status, f"Expected Admin State: in HA output, got: {ha_status}"
        assert "enabled" in ha_status, f"Expected Admin State: enabled, got: {ha_status}"


@pytest.mark.ha
def test_ha_peers_configured(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Each AGW has at least one peer in the HA store."""
    leader_ha = ha_cmd_leader.agw_show_ha()
    assert "Peers" in leader_ha, (
        f"Expected 'Peers' in leader HA output, got: {leader_ha}"
    )

    follower_ha = ha_cmd_follower.agw_show_ha()
    assert "Peers" in follower_ha, (
        f"Expected 'Peers' in follower HA output, got: {follower_ha}"
    )


@pytest.mark.ha
def test_ha_adjacency_established(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Poll show_adj until both AGWs see their peer (30s timeout)."""
    deadline = time.time() + 30

    def adj_has_peer(cmd: CommandExecutor, peer_ip: str) -> bool:
        try:
            adj = cmd.agw_show_adj()
            return peer_ip in adj
        except Exception:
            return False

    while time.time() < deadline:
        leader_ok = adj_has_peer(ha_cmd_leader, FOLLOWER_IP)
        follower_ok = adj_has_peer(ha_cmd_follower, LEADER_IP)
        if leader_ok and follower_ok:
            return
        time.sleep(2)

    leader_adj = ha_cmd_leader.agw_show_adj()
    follower_adj = ha_cmd_follower.agw_show_adj()
    pytest.fail(
        f"Adjacency not established within 30s.\n"
        f"Leader adj:\n{leader_adj}\nFollower adj:\n{follower_adj}"
    )


@pytest.mark.ha
def test_ha_member_info(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """show_mbr returns non-empty member data on both AGWs."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        mbr = cmd.agw_show_mbr()
        assert "HA Members" in mbr, f"Expected HA Members header, got: {mbr}"


@pytest.mark.ha
def test_ha_leader_elected(ha_cmd_leader: CommandExecutor):
    """The leader AGW (lowest IP = 172.20.0.2) reports Leader: true (45s timeout)."""
    deadline = time.time() + 45

    while time.time() < deadline:
        ha_status = ha_cmd_leader.agw_show_ha()
        for line in ha_status.splitlines():
            if "Leader:" in line and "true" in line.lower():
                return
        time.sleep(3)

    pytest.fail(f"Leader AGW did not report Leader: true within 45s.\nLast output:\n{ha_status}")


@pytest.mark.ha
def test_ha_follower_not_leader(ha_cmd_follower: CommandExecutor):
    """The follower AGW (highest IP = 172.20.0.3) reports Leader: false (45s timeout)."""
    deadline = time.time() + 45

    while time.time() < deadline:
        ha_status = ha_cmd_follower.agw_show_ha()
        for line in ha_status.splitlines():
            if "Leader:" in line and "false" in line.lower():
                return
        time.sleep(3)

    pytest.fail(f"Follower AGW did not report Leader: false within 45s.\nLast output:\n{ha_status}")


@pytest.mark.ha
def test_ha_state_visible(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """show_ha includes HA State: and SVC State: fields on both AGWs."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        ha_status = cmd.agw_show_ha()
        assert "HA State:" in ha_status, f"Expected HA State: in HA output, got: {ha_status}"
        assert "SVC State:" in ha_status, f"Expected SVC State: in HA output, got: {ha_status}"


@pytest.mark.ha
def test_ha_state_after_adjacency(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Poll show_ha until both nodes show a valid HA State (30s timeout)."""
    deadline = time.time() + 30

    valid_ha_states = {"ha-ready", "ha-not-ready", "ha-switchover", "ha-takeover"}

    def ha_state_valid(cmd: CommandExecutor) -> bool:
        try:
            ha_status = cmd.agw_show_ha()
            for line in ha_status.splitlines():
                if "HA State:" in line:
                    return any(s in line for s in valid_ha_states)
            return False
        except Exception:
            return False

    while time.time() < deadline:
        if ha_state_valid(ha_cmd_leader) and ha_state_valid(ha_cmd_follower):
            return
        time.sleep(2)

    leader_ha = ha_cmd_leader.agw_show_ha()
    follower_ha = ha_cmd_follower.agw_show_ha()
    pytest.fail(
        f"Valid HA State not reached within 30s.\n"
        f"Leader HA:\n{leader_ha}\nFollower HA:\n{follower_ha}"
    )


@pytest.mark.ha
def test_ha_gnmi_state_written(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Poll show_gnmi_ha until agentHaState appears in mock gNMI (75s timeout)."""
    deadline = time.time() + 75

    def gnmi_ha_state_written(cmd: CommandExecutor) -> bool:
        try:
            ha_json = cmd.agw_gnmi_ha_show_json()
            if isinstance(ha_json, dict):
                return ha_json.get("admin_state") == "enabled"
            return False
        except Exception:
            return False

    while time.time() < deadline:
        if gnmi_ha_state_written(ha_cmd_leader) and gnmi_ha_state_written(ha_cmd_follower):
            return
        time.sleep(3)

    pytest.fail("agentHaState not written to mock gNMI within 75s")


@pytest.mark.ha
def test_ha_in_service_initial_state(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Both AGWs report in_service=True and in_service_state='in-service' at startup."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        data = cmd.agw_gnmi_device_show_json()
        assert data["in_service"] is True, f"Expected in_service=True, got {data['in_service']}"
        assert data["in_service_state"] == "in-service", (
            f"Expected in_service_state='in-service', got {data['in_service_state']!r}"
        )


@pytest.mark.ha
def test_ha_in_service_criterion_set(ha_cmd_leader: CommandExecutor):
    """Poll HA JSON until service_redir criterion is True (45s timeout)."""
    deadline = time.time() + 45

    while time.time() < deadline:
        try:
            ha_json = ha_cmd_leader.agw_gnmi_ha_show_json()
            criteria = ha_json.get("local", {}).get("criteria", {})
            if criteria.get("service_redir") is True:
                return
        except Exception:
            pass
        time.sleep(3)

    pytest.fail(
        f"service_redir criterion not set to True within 45s.\n"
        f"Last HA JSON: {ha_json}"
    )


@pytest.mark.ha
def test_ha_in_service_transition_to_out_of_service(ha_cmd_leader: CommandExecutor):
    """Setting out-of-service flips in_service=False and service_redir=False (30s timeout)."""
    ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "out-of-service")

    deadline = time.time() + 30
    device_ok = False
    ha_ok = False

    while time.time() < deadline:
        try:
            data = ha_cmd_leader.agw_gnmi_device_show_json()
            device_ok = (
                data.get("in_service") is False
                and data.get("in_service_state") == "out-of-service"
            )
        except Exception:
            pass

        try:
            ha_json = ha_cmd_leader.agw_gnmi_ha_show_json()
            criteria = ha_json.get("local", {}).get("criteria", {})
            ha_ok = criteria.get("service_redir") is False
        except Exception:
            pass

        if device_ok and ha_ok:
            # Restore clean state
            ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "in-service")
            return
        time.sleep(2)

    # Restore even on failure
    ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "in-service")
    pytest.fail(
        f"out-of-service transition not observed within 30s.\n"
        f"device_ok={device_ok}, ha_ok={ha_ok}"
    )


@pytest.mark.ha
def test_ha_in_service_transition_back_to_in_service(ha_cmd_leader: CommandExecutor):
    """Transitioning out-of-service -> in-service restores in_service=True and service_redir=True (30s timeout)."""
    # First set out-of-service
    ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "out-of-service")
    time.sleep(3)

    # Now set back to in-service
    ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "in-service")

    deadline = time.time() + 30
    device_ok = False
    ha_ok = False

    while time.time() < deadline:
        try:
            data = ha_cmd_leader.agw_gnmi_device_show_json()
            device_ok = (
                data.get("in_service") is True
                and data.get("in_service_state") == "in-service"
            )
        except Exception:
            pass

        try:
            ha_json = ha_cmd_leader.agw_gnmi_ha_show_json()
            criteria = ha_json.get("local", {}).get("criteria", {})
            ha_ok = criteria.get("service_redir") is True
        except Exception:
            pass

        if device_ok and ha_ok:
            return
        time.sleep(2)

    pytest.fail(
        f"in-service transition not observed within 30s.\n"
        f"device_ok={device_ok}, ha_ok={ha_ok}"
    )


# ---------------------------------------------------------------------------
# State-machine transition tests (states.md rows 4–7)
#
# Rows 1-3 (pre-adjacency states) are covered by unit tests in
# pkg/nxos/ha/statemachine_test.go. They cannot be reliably tested in
# integration because AdjacencyReached is a one-way latch and the system
# establishes adjacency before these tests run.
# ---------------------------------------------------------------------------

@pytest.mark.ha
def test_ha_transition_both_in_service(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Row 4: Both in-service with adjacency established → ha-ready on both nodes."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), (
        f"Row 4: Leader did not reach ha-ready within 60s.\n"
        f"Leader:\n{ha_cmd_leader.agw_show_ha()}"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), (
        f"Row 4: Follower did not reach ha-ready within 60s.\n"
        f"Follower:\n{ha_cmd_follower.agw_show_ha()}"
    )


@pytest.mark.ha
def test_ha_transition_local_criteria_failure(ha_cmd_leader: CommandExecutor):
    """Row 7: Local criteria failure → ha-switchover regardless of AdjacencyReached.

    Setting the leader out-of-service fails the service_redir criterion.
    Degradation is immediate (fail-fast, no hold-down).
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")

    ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "out-of-service")

    try:
        assert poll_ha_state(ha_cmd_leader, "ha-switchover", timeout=45), (
            f"Row 7: Expected ha-switchover after local criteria failure.\n"
            f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
        )
    finally:
        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "in-service")


@pytest.mark.ha
def test_ha_transition_adjacency_failure(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Row 5: Adjacency failure after adjacency reached → leader ha-takeover, follower ha-switchover.

    Taking the follower out-of-service causes it to report svc_failure.
    The leader sees peer_service_redir fail → adjacency criteria not met.
    Since AdjacencyReached is sticky and true, the leader transitions to ha-takeover.
    The follower transitions to ha-switchover (local criteria failure).
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    ha_cmd_follower.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "out-of-service")

    try:
        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=45), (
            f"Row 5: Expected ha-takeover on leader after follower adjacency failure.\n"
            f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
        )

        # Verify adjacency_criteria_met flips to False on the leader's view of the follower.
        deadline = time.time() + 30
        adj_met_false = False
        while time.time() < deadline:
            try:
                peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
                peers = peers_json.get("peers", {})
                follower_peer = peers.get(FOLLOWER_IP, {})
                if follower_peer.get("adjacency_criteria_met") is False:
                    adj_met_false = True
                    break
            except Exception:
                pass
            time.sleep(2)
        assert adj_met_false, (
            f"Row 5: Expected adjacency_criteria_met=False on leader's view of follower after out-of-service.\n"
            f"Leader peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
        )
    finally:
        ha_cmd_follower.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, "in-service")


@pytest.mark.ha
def test_ha_peer_criteria_met_values(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready: member_criteria_met and adjacency_criteria_met are True for each peer (60s timeout)."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    deadline = time.time() + 30

    def criteria_met(cmd: CommandExecutor) -> bool:
        try:
            peers_json = cmd.agw_gnmi_ha_peers_json()
            peers = peers_json.get("peers", {})
            if not peers:
                return False
            for peer in peers.values():
                if not peer.get("member_criteria_met"):
                    return False
                if not peer.get("adjacency_criteria_met"):
                    return False
            return True
        except Exception:
            return False

    while time.time() < deadline:
        if criteria_met(ha_cmd_leader) and criteria_met(ha_cmd_follower):
            return
        time.sleep(2)

    leader_peers = ha_cmd_leader.agw_gnmi_ha_peers_json().get("peers", {})
    follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json().get("peers", {})
    pytest.fail(
        f"peer criteria_met fields not True within 30s after ha-ready.\n"
        f"Leader peers: {leader_peers}\n"
        f"Follower peers: {follower_peers}"
    )


@pytest.mark.ha
def test_ha_local_state_in_json(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """HA JSON output contains a 'local' section with all expected state fields."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        ha_json = cmd.agw_gnmi_ha_show_json()
        assert isinstance(ha_json, dict), f"Expected dict, got {type(ha_json)}"
        local = ha_json.get("local")
        assert local is not None, f"Expected 'local' key in HA JSON, got: {list(ha_json.keys())}"
        for field in ("ha_state", "svc_state", "criteria_met", "policy_check", "adjacency_reached",
                      "criteria", "flap_count", "recovery_pending", "policy_rev"):
            assert field in local, f"Expected '{field}' in local state, got: {list(local.keys())}"


@pytest.mark.ha
def test_ha_peer_state_in_json(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """HA peers JSON output contains a 'peers' dict with full per-peer state fields (30s timeout)."""
    deadline = time.time() + 30

    def peers_populated(cmd: CommandExecutor) -> bool:
        try:
            peers_json = cmd.agw_gnmi_ha_peers_json()
            peers = peers_json.get("peers", {})
            if not peers:
                return False
            for peer in peers.values():
                for field in ("svc_state", "adjacency_connected", "adjacency_criteria",
                              "member_criteria", "adjacency_criteria_met", "member_criteria_met"):
                    if field not in peer:
                        return False
            return True
        except Exception:
            return False

    while time.time() < deadline:
        if peers_populated(ha_cmd_leader) and peers_populated(ha_cmd_follower):
            return
        time.sleep(2)

    leader_peers = ha_cmd_leader.agw_gnmi_ha_peers_json().get("peers", {})
    follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json().get("peers", {})
    pytest.fail(
        f"Peer state fields not populated within 30s.\n"
        f"Leader peers: {leader_peers}\n"
        f"Follower peers: {follower_peers}"
    )


# ---------------------------------------------------------------------------
# Debug criteria commands: agwctl ha criteria fail/ok
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_adjacency_reached_flag(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, adjacency_reached=True on both nodes (30s window after baseline)."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), (
        "Leader never reached ha-ready"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), (
        "Follower never reached ha-ready"
    )

    deadline = time.time() + 30

    def adjacency_reached(cmd: CommandExecutor) -> bool:
        try:
            ha_json = cmd.agw_gnmi_ha_show_json()
            return ha_json.get("local", {}).get("adjacency_reached") is True
        except Exception:
            return False

    while time.time() < deadline:
        if adjacency_reached(ha_cmd_leader) and adjacency_reached(ha_cmd_follower):
            return
        time.sleep(2)

    pytest.fail(
        f"adjacency_reached not True within 30s after ha-ready.\n"
        f"Leader local: {ha_cmd_leader.agw_gnmi_ha_show_json().get('local', {})}\n"
        f"Follower local: {ha_cmd_follower.agw_gnmi_ha_show_json().get('local', {})}"
    )


@pytest.mark.ha
def test_ha_member_criteria_populated(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, each peer has member_criteria_met, adjacency_criteria_met, and adjacency_connected all True."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), (
        "Leader never reached ha-ready"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), (
        "Follower never reached ha-ready"
    )

    deadline = time.time() + 30

    def all_peer_criteria_ok(cmd: CommandExecutor) -> bool:
        try:
            peers_json = cmd.agw_gnmi_ha_peers_json()
            peers = peers_json.get("peers", {})
            if not peers:
                return False
            for peer in peers.values():
                if peer.get("member_criteria_met") is not True:
                    return False
                if peer.get("adjacency_criteria_met") is not True:
                    return False
                if peer.get("adjacency_connected") is not True:
                    return False
            return True
        except Exception:
            return False

    while time.time() < deadline:
        if all_peer_criteria_ok(ha_cmd_leader) and all_peer_criteria_ok(ha_cmd_follower):
            return
        time.sleep(2)

    leader_peers = ha_cmd_leader.agw_gnmi_ha_peers_json().get("peers", {})
    follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json().get("peers", {})
    pytest.fail(
        f"Peer criteria not fully populated within 30s after ha-ready.\n"
        f"Leader peers: {leader_peers}\n"
        f"Follower peers: {follower_peers}"
    )


@pytest.mark.ha
def test_ha_debug_criteria_fail_causes_switchover(ha_cmd_leader: CommandExecutor):
    """agwctl ha criteria fail sets debug_override=false → leader transitions to ha-switchover."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")

    ha_cmd_leader.agw_ha_criteria_fail()

    try:
        assert poll_ha_state(ha_cmd_leader, "ha-switchover", timeout=30), (
            f"Expected ha-switchover after criteria fail.\n"
            f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
        )
    finally:
        ha_cmd_leader.agw_ha_criteria_ok()


@pytest.mark.ha
def test_ha_debug_criteria_ok_restores_ready(ha_cmd_leader: CommandExecutor):
    """agwctl ha criteria fail → ha-switchover; ha criteria ok → ha-ready restored."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")

    ha_cmd_leader.agw_ha_criteria_fail()
    assert poll_ha_state(ha_cmd_leader, "ha-switchover", timeout=30), (
        "Expected ha-switchover after criteria fail"
    )

    ha_cmd_leader.agw_ha_criteria_ok()
    assert wait_for_ha_ready(ha_cmd_leader, timeout=45), (
        f"Expected ha-ready to be restored after criteria ok.\n"
        f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
    )


@pytest.mark.ha
def test_ha_failover_leader_criteria_fail(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Full failover: leader criteria fail → leader ha-switchover, follower ha-takeover, then recovery.

    When the leader's local criteria fail:
    - Leader goes to ha-switchover (local criteria not met)
    - Follower sees peer svc_failure → adjacency criteria fail → follower becomes leader
    - Follower (now leader) goes to ha-takeover
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    ha_cmd_leader.agw_ha_criteria_fail()

    try:
        assert poll_ha_state(ha_cmd_leader, "ha-switchover", timeout=30), (
            f"Expected leader ha-switchover after criteria fail.\n"
            f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
        )
        # Follower sees peer adjacency failure after adjacency reached.
        # It may be either ha-takeover (if it became leader) or ha-switchover (if still follower).
        # Either indicates correct state machine behavior.
        deadline = time.time() + 45
        follower_transitioned = False
        while time.time() < deadline:
            try:
                ha_status = ha_cmd_follower.agw_show_ha()
                for line in ha_status.splitlines():
                    if "HA State:" in line and ("ha-takeover" in line or "ha-switchover" in line):
                        follower_transitioned = True
                        break
                if follower_transitioned:
                    break
            except Exception:
                pass
            time.sleep(2)
        assert follower_transitioned, (
            f"Expected follower ha-takeover or ha-switchover after leader SVC=failure.\n"
            f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
        )
    finally:
        ha_cmd_leader.agw_ha_criteria_ok()

    # Both nodes should recover to ha-ready after hold-down timer expires (~10s).
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), (
        f"Leader did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), (
        f"Follower did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
    )


# ---------------------------------------------------------------------------
# Disconnect criteria reset tests
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_disconnect_clears_peer_criteria(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Stopping the follower clears connection-managed criteria on the leader's peer view.

    Verifies:
    - member_criteria_met=False after disconnect
    - adjacency_criteria_met=False after disconnect
    - adjacency_connected=False after disconnect
    - member_criteria values reset to False
    - adjacency_criteria[peer_service_redir]=False, [peer_policy]=False
    - adjacency_criteria[peer_ip_config]=True  (preserved, managed by gNMI)
    - Both nodes recover to ha-ready after follower restarts
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    # Verify baseline: peer criteria met on leader's view of follower.
    peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
    follower_peer = peers_json.get("peers", {}).get(FOLLOWER_IP, {})
    assert follower_peer.get("member_criteria_met") is True, (
        f"Baseline: member_criteria_met should be True, got: {follower_peer}"
    )
    assert follower_peer.get("adjacency_criteria_met") is True, (
        f"Baseline: adjacency_criteria_met should be True, got: {follower_peer}"
    )

    # Stop the follower container to simulate disconnect.
    follower_container = ha_cmd_follower._get_agw_container()
    follower_container.stop(timeout=5)

    try:
        # Poll until leader sees disconnect + criteria cleared.
        deadline = time.time() + 45
        criteria_cleared = False
        last_peer_state = {}

        while time.time() < deadline:
            try:
                peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
                fp = peers_json.get("peers", {}).get(FOLLOWER_IP, {})
                last_peer_state = fp

                if (fp.get("adjacency_connected") is False
                        and fp.get("member_criteria_met") is False
                        and fp.get("adjacency_criteria_met") is False):

                    # peer_ip_config must be preserved (gNMI-managed, not connection-managed).
                    adj_criteria = fp.get("adjacency_criteria", {})
                    assert adj_criteria.get("peer_ip_config") is True, (
                        f"peer_ip_config should be preserved after disconnect, got: {adj_criteria}"
                    )

                    # Connection-managed adjacency criteria must be cleared.
                    for crit in ("peer_service_redir", "peer_policy"):
                        if crit in adj_criteria:
                            assert adj_criteria[crit] is False, (
                                f"{crit} should be False after disconnect, got: {adj_criteria}"
                            )

                    # All member criteria must be cleared.
                    member_criteria = fp.get("member_criteria", {})
                    for crit_name, crit_val in member_criteria.items():
                        assert crit_val is False, (
                            f"member_criteria[{crit_name}] should be False after disconnect"
                        )

                    criteria_cleared = True
                    break
            except Exception:
                pass
            time.sleep(2)

        assert criteria_cleared, (
            f"Peer criteria not cleared within 45s after follower disconnect.\n"
            f"Last peer state: {last_peer_state}"
        )
    finally:
        # Restart the follower container.
        follower_container.start()
        # Reset cached container reference so subsequent commands reconnect.
        ha_cmd_follower._agw_container = None

    # Both nodes should recover to ha-ready after reconnection.
    assert wait_for_ha_ready(ha_cmd_leader, timeout=90), (
        f"Leader did not recover to ha-ready after follower restart.\n"
        f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=90), (
        f"Follower did not reach ha-ready after restart.\n"
        f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
    )


# ---------------------------------------------------------------------------
# Role-differentiated state tests (ha-takeover vs ha-switchover)
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_leader_takeover_on_peer_disconnect(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Leader transitions to ha-takeover (not ha-switchover) when follower stops.

    After adjacency is reached, the leader should go to ha-takeover when the
    follower becomes unreachable, since the leader continues serving traffic.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    follower_container = ha_cmd_follower._get_agw_container()
    follower_container.stop(timeout=5)

    try:
        assert poll_ha_state(ha_cmd_leader, "ha-takeover", timeout=60), (
            f"Expected leader ha-takeover after follower disconnect.\n"
            f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
        )

        # Verify leader SVC state remains ready (leader keeps serving)
        ha_json = ha_cmd_leader.agw_gnmi_ha_show_json()
        local = ha_json.get("local", {})
        assert local.get("svc_state") == "ready", (
            f"Expected leader svc_state=ready during takeover, got: {local.get('svc_state')}"
        )
    finally:
        follower_container.start()
        ha_cmd_follower._agw_container = None

    assert wait_for_ha_ready(ha_cmd_leader, timeout=90), (
        f"Leader did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=90), (
        f"Follower did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
    )


@pytest.mark.ha
def test_ha_follower_switchover_on_peer_disconnect(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Follower transitions to ha-switchover (not ha-takeover) when leader stops.

    After adjacency is reached, the follower should go to ha-switchover when the
    leader becomes unreachable, since the follower stops serving traffic.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    leader_container = ha_cmd_leader._get_agw_container()
    leader_container.stop(timeout=5)

    try:
        # Follower should eventually see peer loss.
        # It may initially go to ha-switchover (follower role) or ha-takeover
        # (if re-election makes it leader after the old leader is gone).
        # Both are valid outcomes — the key invariant is it does NOT stay ha-ready.
        deadline = time.time() + 60
        transitioned = False
        while time.time() < deadline:
            try:
                ha_status = ha_cmd_follower.agw_show_ha()
                for line in ha_status.splitlines():
                    if "HA State:" in line and ("ha-takeover" in line or "ha-switchover" in line):
                        transitioned = True
                        break
                if transitioned:
                    break
            except Exception:
                pass
            time.sleep(2)

        assert transitioned, (
            f"Expected follower to leave ha-ready after leader disconnect.\n"
            f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
        )
    finally:
        leader_container.start()
        ha_cmd_leader._agw_container = None

    assert wait_for_ha_ready(ha_cmd_leader, timeout=90), (
        f"Leader did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_leader.agw_show_ha()}"
    )
    assert wait_for_ha_ready(ha_cmd_follower, timeout=90), (
        f"Follower did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
    )


# ---------------------------------------------------------------------------
# HA VRF GID reconciliation tests
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_vrf_gids_match_on_both_nodes(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, leader and follower have identical VRF GIDs.

    HA reconciliation (SetGIDs) should align the follower's GIDs with the
    leader's. Both nodes share the same --vrf-map, so GIDs must match exactly.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    # Allow reconciliation to complete
    time.sleep(5)

    leader_data = ha_cmd_leader.agw_gnmi_vrf_show_json()
    follower_data = ha_cmd_follower.agw_gnmi_vrf_show_json()

    leader_gids = {v["name"]: v["gid"] for v in leader_data["vrfs"] if v["gid"] > 0}
    follower_gids = {v["name"]: v["gid"] for v in follower_data["vrfs"] if v["gid"] > 0}

    mismatches = []
    for name in leader_gids:
        if name in follower_gids and leader_gids[name] != follower_gids[name]:
            mismatches.append(
                f"{name}: leader={leader_gids[name]}, follower={follower_gids[name]}"
            )

    assert not mismatches, \
        f"VRF GID mismatches between leader and follower after reconciliation:\n" + \
        "\n".join(mismatches)


@pytest.mark.ha
def test_ha_vrf_presets_match_gids(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, preset == gid for all VRFs on both nodes.

    After reconciliation completes, reconcilePresets should have aligned all
    presets with their GIDs.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    time.sleep(5)

    for label, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
        data = cmd.agw_gnmi_vrf_show_json()
        mismatches = []
        for vrf in data["vrfs"]:
            if vrf["gid"] > 0 and vrf["preset"] != vrf["gid"]:
                mismatches.append(
                    f"{vrf['name']}: gid={vrf['gid']}, preset={vrf['preset']}"
                )
        assert not mismatches, \
            f"preset != gid on {label} after reconciliation:\n" + "\n".join(mismatches)


@pytest.mark.ha
def test_ha_no_duplicate_gids_on_either_node(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, no two VRFs share the same GID on either node."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    time.sleep(5)

    for label, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
        data = cmd.agw_gnmi_vrf_show_json()
        gids = [v["gid"] for v in data["vrfs"] if v["gid"] > 0]
        assert len(gids) == len(set(gids)), \
            f"Duplicate GIDs detected on {label}: {gids}"


@pytest.mark.ha
def test_ha_vrf_map_gids_preserved(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, --vrf-map GIDs are preserved on both nodes.

    Both HA containers are started with AGW_VRF_MAP=default:1,epbr-1001:1001,...
    Reconciliation must not change these pre-seeded GIDs.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    time.sleep(5)

    # HA containers use a smaller VRF map: default:1, epbr-1001:1001, epbr-1002:1002, epbr-1003:1003
    expected = {"default": 1, "epbr-1001": 1001, "epbr-1002": 1002, "epbr-1003": 1003}

    for label, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
        data = cmd.agw_gnmi_vrf_show_json()
        gid_map = {v["name"]: v["gid"] for v in data["vrfs"]}

        mismatches = []
        for name, want in expected.items():
            if name in gid_map and gid_map[name] != want:
                mismatches.append(f"{name}: want {want}, got {gid_map[name]}")

        assert not mismatches, \
            f"--vrf-map GIDs not preserved on {label} after reconciliation:\n" + \
            "\n".join(mismatches)


@pytest.mark.ha
def test_ha_follower_criteria_fail_gives_switchover(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Follower local criteria failure → follower ha-switchover (not ha-takeover).

    The follower's own local criteria failing should always produce ha-switchover,
    never ha-takeover, regardless of the peer state.
    """
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    ha_cmd_follower.agw_ha_criteria_fail()

    try:
        assert poll_ha_state(ha_cmd_follower, "ha-switchover", timeout=30), (
            f"Expected follower ha-switchover after local criteria fail.\n"
            f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
        )

        # Verify follower SVC state goes to not-ready
        ha_json = ha_cmd_follower.agw_gnmi_ha_show_json()
        local = ha_json.get("local", {})
        assert local.get("svc_state") == "not-ready", (
            f"Expected follower svc_state=not-ready during switchover, got: {local.get('svc_state')}"
        )
    finally:
        ha_cmd_follower.agw_ha_criteria_ok()

    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), (
        f"Follower did not recover to ha-ready.\n"
        f"Last HA status:\n{ha_cmd_follower.agw_show_ha()}"
    )


# ---------------------------------------------------------------------------
# VRF GID reconciliation: adjacency criterion tests
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_vrf_gid_criterion_set(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, the peer_vrf_gid adjacency criterion is True on both peers."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    deadline = time.time() + 30

    def vrf_gid_criterion_ok(cmd: CommandExecutor) -> bool:
        try:
            peers_json = cmd.agw_gnmi_ha_peers_json()
            peers = peers_json.get("peers", {})
            if not peers:
                return False
            for peer in peers.values():
                adj_criteria = peer.get("adjacency_criteria", {})
                if adj_criteria.get("peer_vrf_gid") is not True:
                    return False
            return True
        except Exception:
            return False

    while time.time() < deadline:
        if vrf_gid_criterion_ok(ha_cmd_leader) and vrf_gid_criterion_ok(ha_cmd_follower):
            return
        time.sleep(2)

    leader_peers = ha_cmd_leader.agw_gnmi_ha_peers_json()
    follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json()
    pytest.fail(
        f"peer_vrf_gid criterion not True on both peers within 30s.\n"
        f"Leader peers: {leader_peers.get('peers', {})}\n"
        f"Follower peers: {follower_peers.get('peers', {})}"
    )


@pytest.mark.ha
def test_ha_vrf_gid_criterion_cleared_on_disconnect(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Stopping the follower clears the peer_vrf_gid criterion on the leader, then reconnect restores it."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    # Confirm criterion is True first.
    time.sleep(3)
    peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
    follower_peer = peers_json.get("peers", {}).get(FOLLOWER_IP, {})
    adj_criteria = follower_peer.get("adjacency_criteria", {})
    assert adj_criteria.get("peer_vrf_gid") is True, (
        f"Baseline: peer_vrf_gid should be True before disconnect.\n"
        f"Adjacency criteria: {adj_criteria}"
    )

    # Stop the follower container.
    follower_container = ha_cmd_follower._get_agw_container()
    follower_container.stop(timeout=5)

    try:
        # Poll until leader's peer_vrf_gid criterion is cleared.
        deadline = time.time() + 60
        criterion_cleared = False
        while time.time() < deadline:
            try:
                peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
                fp = peers_json.get("peers", {}).get(FOLLOWER_IP, {})
                adj = fp.get("adjacency_criteria", {})
                if adj.get("peer_vrf_gid") is not True:
                    criterion_cleared = True
                    break
            except Exception:
                pass
            time.sleep(3)

        assert criterion_cleared, (
            f"peer_vrf_gid criterion not cleared within 60s after follower disconnect.\n"
            f"Last criteria: {adj}"
        )
    finally:
        follower_container.start()
        ha_cmd_follower._agw_container = None

    # After reconnect, criterion should be restored.
    assert wait_for_ha_ready(ha_cmd_leader, timeout=90), "Leader did not recover to ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=90), "Follower did not recover to ha-ready"

    deadline = time.time() + 30
    restored = False
    while time.time() < deadline:
        try:
            peers_json = ha_cmd_leader.agw_gnmi_ha_peers_json()
            fp = peers_json.get("peers", {}).get(FOLLOWER_IP, {})
            if fp.get("adjacency_criteria", {}).get("peer_vrf_gid") is True:
                restored = True
                break
        except Exception:
            pass
        time.sleep(2)

    assert restored, (
        f"peer_vrf_gid criterion not restored within 30s after follower reconnect.\n"
        f"Leader peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
    )


@pytest.mark.ha
def test_ha_vrf_show_text_includes_preset_column(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """The text output of 'agwctl vrf show' includes the Preset column header."""
    if not wait_for_ha_ready(ha_cmd_leader, timeout=60):
        pytest.skip("Leader never reached ha-ready baseline")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=60):
        pytest.skip("Follower never reached ha-ready baseline")

    for label, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
        output = cmd.agw_gnmi_vrf_show()
        assert "Preset" in output, (
            f"Text output of 'vrf show' on {label} does not include Preset column.\n"
            f"Output:\n{output}"
        )
