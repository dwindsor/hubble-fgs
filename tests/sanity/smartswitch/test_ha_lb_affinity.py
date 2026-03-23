#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA integration tests for LB mode membership criteria and VRF/VLAN affinity.

Tests validate:
1. LB mode is exchanged between peers via adjacency (member_info.lb_mode)
2. LB mode mismatch causes membership failure (peer_compatible=False)
3. LB mode match is reflected in both device store and peer member info
4. VRF affinity is set to 65535 in symmetric_hash mode (all DPUs)
5. LB mode can be changed at runtime via mock gNMI and propagates correctly
"""

import time
import pytest
import logging

from helper.command_executor import CommandExecutor
from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, poll_peer_compatible, get_peer_lb_mode,
)
from helper.gnmi_paths import LB_MODE_PATH

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LB mode in device store and adjacency exchange
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_lb_mode_in_device_store(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Both AGWs report lb_mode in device store JSON (default: symmetric_hash)."""
    for cmd in (ha_cmd_leader, ha_cmd_follower):
        data = cmd.agw_gnmi_device_show_json()
        lb_mode = data.get("lb_mode")
        assert lb_mode is not None, f"Expected lb_mode in device store, got keys: {list(data.keys())}"
        assert lb_mode == "symmetric_hash", f"Expected default lb_mode='symmetric_hash', got '{lb_mode}'"


@pytest.mark.ha
def test_ha_lb_mode_in_peer_member_info(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """After ha-ready, the leader's view of the follower member_info contains lb_mode (30s timeout).

    Note: Only the adjacency initiator (leader) populates full member_info
    from the response. The server side (follower) validates membership
    criteria but may not expose the full member_info in JSON output.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    deadline = time.time() + 30

    while time.time() < deadline:
        try:
            lb_mode = get_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP)
            if lb_mode == "symmetric_hash":
                return
        except Exception:
            pass
        time.sleep(2)

    pytest.fail(
        f"Leader does not see follower lb_mode='symmetric_hash' within 30s.\n"
        f"Leader sees: '{get_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP)}'"
    )


@pytest.mark.ha
def test_ha_lb_mode_peers_match(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """The follower's local device lb_mode matches what the leader sees in member_info.

    The leader initiates adjacency and receives the follower's member_info
    in the response, which should include the follower's lb_mode value.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    time.sleep(5)  # Allow adjacency exchange

    follower_local = ha_cmd_follower.agw_gnmi_device_show_json().get("lb_mode")
    leader_sees_follower = get_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP)

    assert follower_local == leader_sees_follower, (
        f"Follower local lb_mode='{follower_local}' != what leader sees='{leader_sees_follower}'"
    )


# ---------------------------------------------------------------------------
# LB mode mismatch causes membership failure
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_lb_mode_mismatch_causes_member_failure(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Changing lb_mode on one peer causes peer_compatible=False on the other (45s timeout).

    Steps:
    1. Ensure ha-ready baseline
    2. Change leader's lb_mode to dpu_pinning (follower stays symmetric_hash)
    3. Verify follower sees peer_compatible=False for the leader
    4. Restore leader's lb_mode to symmetric_hash
    5. Verify recovery back to peer_compatible=True
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    # Verify baseline: peer_compatible=True on follower's view of leader
    assert poll_peer_compatible(ha_cmd_follower, LEADER_IP, expected=True, timeout=30), (
        f"Baseline: follower should see peer_compatible=True for leader"
    )

    # Change leader's lb_mode to dpu_pinning to create mismatch
    ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "dpu_pinning")

    try:
        # Verify the leader's device store updated
        deadline = time.time() + 15
        while time.time() < deadline:
            data = ha_cmd_leader.agw_gnmi_device_show_json()
            if data.get("lb_mode") == "dpu_pinning":
                break
            time.sleep(2)
        else:
            pytest.fail("Leader device store did not update lb_mode to dpu_pinning")

        # Follower should see peer_compatible=False for the leader (mismatch)
        assert poll_peer_compatible(ha_cmd_follower, LEADER_IP, expected=False, timeout=45), (
            f"Expected follower to see peer_compatible=False after lb_mode mismatch.\n"
            f"Follower HA JSON peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
        )

        # Also verify leader sees the follower peer_compatible=False (symmetric != dpu_pinning)
        assert poll_peer_compatible(ha_cmd_leader, FOLLOWER_IP, expected=False, timeout=45), (
            f"Expected leader to see peer_compatible=False after lb_mode mismatch.\n"
            f"Leader HA JSON peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
        )
    finally:
        # Restore lb_mode
        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "symmetric_hash")

    # Verify recovery: peer_compatible=True on both after lb_mode restored
    assert poll_peer_compatible(ha_cmd_follower, LEADER_IP, expected=True, timeout=60), (
        f"Follower did not recover peer_compatible=True after lb_mode restored.\n"
        f"Follower HA JSON peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
    )
    assert poll_peer_compatible(ha_cmd_leader, FOLLOWER_IP, expected=True, timeout=60), (
        f"Leader did not recover peer_compatible=True after lb_mode restored.\n"
        f"Leader HA JSON peers: {ha_cmd_leader.agw_gnmi_ha_peers_json().get('peers', {})}"
    )


@pytest.mark.ha
def test_ha_lb_mode_mismatch_sets_peer_svc_not_ready(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """LB mode mismatch causes peer svc_state=not-ready and leader ha-takeover, then recovers.

    Membership failure (peer_compatible=False) causes the peer's svc_state to
    become not-ready and the leader transitions to ha-takeover.
    Restoring matching lb_mode recovers the peer to svc_state=ready.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    # Create mismatch
    ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "dpu_pinning")

    try:
        # Follower should see the leader's peer svc_state=not-ready
        deadline = time.time() + 45
        mbr_fail_seen = False
        while time.time() < deadline:
            try:
                follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json()
                leader_peer = follower_peers.get("peers", {}).get(LEADER_IP, {})
                if leader_peer.get("svc_state") == "not-ready":
                    mbr_fail_seen = True
                    break
            except Exception:
                pass
            time.sleep(2)

        assert mbr_fail_seen, (
            f"Expected follower to see leader peer svc_state=not-ready after lb_mode mismatch.\n"
            f"Follower peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
        )

        # Leader should go to ha-takeover (peer membership failed after adjacency reached)
        leader_ha = ha_cmd_leader.agw_gnmi_ha_show_json()
        leader_local = leader_ha.get("local", {})
        assert leader_local.get("ha_state") == "ha-takeover", (
            f"Expected leader ha_state=ha-takeover after peer membership failure, "
            f"got: {leader_local.get('ha_state')}"
        )
    finally:
        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "symmetric_hash")

    # Both should recover: peer svc_state back to ready
    deadline = time.time() + 60
    recovered = False
    while time.time() < deadline:
        try:
            follower_peers = ha_cmd_follower.agw_gnmi_ha_peers_json()
            leader_peer = follower_peers.get("peers", {}).get(LEADER_IP, {})
            if leader_peer.get("svc_state") == "ready":
                recovered = True
                break
        except Exception:
            pass
        time.sleep(2)

    assert recovered, (
        f"Follower did not see leader peer svc_state=ready after lb_mode restored.\n"
        f"Follower peers: {ha_cmd_follower.agw_gnmi_ha_peers_json().get('peers', {})}"
    )


# ---------------------------------------------------------------------------
# LB mode change propagation via adjacency
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_lb_mode_change_propagates_to_peer(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """Changing lb_mode on both peers simultaneously propagates via adjacency exchange.

    Sets both to dpu_pinning, verifies both peers see the new value, then restores.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    # Change both to dpu_pinning simultaneously
    ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "dpu_pinning")
    ha_cmd_follower.agw_mock_gnmi_set(LB_MODE_PATH, "dpu_pinning")

    try:
        # Both device stores should show dpu_pinning
        deadline = time.time() + 15
        while time.time() < deadline:
            leader_lb = ha_cmd_leader.agw_gnmi_device_show_json().get("lb_mode")
            follower_lb = ha_cmd_follower.agw_gnmi_device_show_json().get("lb_mode")
            if leader_lb == "dpu_pinning" and follower_lb == "dpu_pinning":
                break
            time.sleep(2)
        else:
            pytest.fail(
                f"Device stores did not update to dpu_pinning.\n"
                f"Leader: {leader_lb}, Follower: {follower_lb}"
            )

        # After adjacency exchange, both peers should see dpu_pinning in member_info
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                leader_sees = get_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP)
                follower_sees = get_peer_lb_mode(ha_cmd_follower, LEADER_IP)
                if leader_sees == "dpu_pinning" and follower_sees == "dpu_pinning":
                    return
            except Exception:
                pass
            time.sleep(2)

        leader_sees = get_peer_lb_mode(ha_cmd_leader, FOLLOWER_IP)
        follower_sees = get_peer_lb_mode(ha_cmd_follower, LEADER_IP)
        pytest.fail(
            f"Peer member_info lb_mode not updated to dpu_pinning within 30s.\n"
            f"Leader sees follower: '{leader_sees}'\n"
            f"Follower sees leader: '{follower_sees}'"
        )
    finally:
        ha_cmd_leader.agw_mock_gnmi_set(LB_MODE_PATH, "symmetric_hash")
        ha_cmd_follower.agw_mock_gnmi_set(LB_MODE_PATH, "symmetric_hash")
        # Wait for recovery
        wait_for_ha_ready(ha_cmd_leader, timeout=60)
        wait_for_ha_ready(ha_cmd_follower, timeout=60)


# ---------------------------------------------------------------------------
# VRF affinity in symmetric_hash mode
# ---------------------------------------------------------------------------


@pytest.mark.ha
def test_ha_vrf_affinity_symmetric_hash(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """In symmetric_hash mode, VRF affinity field defaults to 0 (dynamic, not pinned).

    The VRF store shows affinity=0 for all VRFs when not in pinning mode,
    indicating no static DPU pinning is configured.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"

    # Verify lb_mode is symmetric_hash
    data = ha_cmd_leader.agw_gnmi_device_show_json()
    assert data.get("lb_mode") == "symmetric_hash", (
        f"Expected symmetric_hash, got {data.get('lb_mode')}"
    )

    # Check VRFs on leader
    vrf_json = ha_cmd_leader.agw_gnmi_vrf_show_json()
    vrfs = vrf_json.get("vrfs", [])
    assert len(vrfs) > 0, "Expected at least one VRF"

    for vrf in vrfs:
        # In symmetric_hash mode, affinity should be 0 (dynamic)
        assert vrf.get("affinity") == 0, (
            f"VRF {vrf['name']}: expected affinity=0 in symmetric_hash mode, got {vrf.get('affinity')}"
        )
        # is_static is derived from affinity: True when affinity >= 1 and != 65535
        assert vrf.get("is_static") is False, (
            f"VRF {vrf['name']}: expected is_static=False for affinity=0 (derived from affinity)"
        )
        # dpu_pinned should be present as an integer
        assert isinstance(vrf.get("dpu_pinned"), int), (
            f"VRF {vrf['name']}: expected dpu_pinned to be present as int"
        )


@pytest.mark.ha
def test_ha_vrf_affinity_consistent_between_peers(ha_cmd_leader: CommandExecutor, ha_cmd_follower: CommandExecutor):
    """VRF affinity values are consistent between leader and follower."""
    assert wait_for_ha_ready(ha_cmd_leader, timeout=60), "Leader never reached ha-ready"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=60), "Follower never reached ha-ready"

    time.sleep(5)

    leader_vrfs = ha_cmd_leader.agw_gnmi_vrf_show_json()
    follower_vrfs = ha_cmd_follower.agw_gnmi_vrf_show_json()

    leader_affinity = {v["name"]: v.get("affinity", -1) for v in leader_vrfs.get("vrfs", [])}
    follower_affinity = {v["name"]: v.get("affinity", -1) for v in follower_vrfs.get("vrfs", [])}

    common_vrfs = set(leader_affinity.keys()) & set(follower_affinity.keys())
    assert len(common_vrfs) > 0, "Expected at least one common VRF"

    mismatches = {}
    for vrf_name in common_vrfs:
        if leader_affinity[vrf_name] != follower_affinity[vrf_name]:
            mismatches[vrf_name] = {
                "leader": leader_affinity[vrf_name],
                "follower": follower_affinity[vrf_name],
            }

    assert not mismatches, (
        f"VRF affinity mismatches between peers: {mismatches}\n"
        f"Leader: {leader_affinity}\nFollower: {follower_affinity}"
    )
