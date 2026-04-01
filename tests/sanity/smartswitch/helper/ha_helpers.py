#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""Shared HA polling and waiting helpers for integration tests.

Consolidates functions that were previously duplicated across test_ha.py,
test_ha_lb_affinity.py, test_ha_member_info_symmetry.py, and
test_vrf_reconcile.py.
"""

import time

from helper.command_executor import CommandExecutor

# IPs assigned by the Makefile HA targets
LEADER_IP = "172.20.0.2"
FOLLOWER_IP = "172.20.0.3"


def wait_for_ha_ready(cmd: CommandExecutor, timeout: int = 60) -> bool:
    """Block until the node reaches ha-ready. Returns True on success."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = cmd.agw_gnmi_ha_show_json()
            if data.get("local", {}).get("ha_state") == "ha-ready":
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def poll_ha_state(cmd: CommandExecutor, expected_state: str, timeout: int = 45) -> bool:
    """Poll ha show JSON until local ha_state equals expected_state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = cmd.agw_gnmi_ha_show_json()
            if data.get("local", {}).get("ha_state") == expected_state:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def get_ha_show_peer(cmd: CommandExecutor, peer_ip: str) -> dict:
    """Return the peer summary dict for peer_ip from ha show --json, or {} if absent."""
    try:
        data = cmd.agw_gnmi_ha_show_json()
        return data.get("peers", {}).get(peer_ip, {})
    except Exception:
        return {}


def poll_peer_membership_ok(cmd: CommandExecutor, peer_ip: str, expected: bool, timeout: int = 45) -> bool:
    """Poll ha show until peers[peer_ip].membership_ok matches expected."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if get_ha_show_peer(cmd, peer_ip).get("membership_ok") is expected:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def poll_peer_service_ok(cmd: CommandExecutor, peer_ip: str, expected: bool, timeout: int = 45) -> bool:
    """Poll ha show until peers[peer_ip].service_ok matches expected."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if get_ha_show_peer(cmd, peer_ip).get("service_ok") is expected:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def get_local_ha_state(cmd: CommandExecutor) -> dict:
    """Return the local HA state dict from ha show JSON.

    The ha show JSON nests local state under 'local'. This helper
    extracts and returns it so callers can access ha_state, svc_state,
    criteria_met, etc. directly.
    """
    data = cmd.agw_gnmi_ha_show_json()
    return data.get("local", data)


# ---------------------------------------------------------------------------
# gNMI log validation helpers
# ---------------------------------------------------------------------------

def get_ha_state_write_sequence(cmd: CommandExecutor, n: int = 50) -> list:
    """Return ordered list of (ts, value) for agentHaState gNMI writes.

    Filters the mock gNMI log for set_notify operations on paths containing
    'agentHaState' and returns them in chronological order.
    """
    try:
        entries = cmd.agw_mock_gnmi_log_json(n=n, prefix="agentHaState", operation="set_notify")
    except Exception:
        entries = []
    results = []
    for entry in entries:
        ts = entry.get("ts", "")
        value = entry.get("value", "").strip('"')
        if value:
            results.append((ts, value))
    return results


def assert_state_transition_order(cmd: CommandExecutor, expected_states: list, n: int = 50):
    """Verify that the gNMI HA state writes match the expected sequence.

    Extracts unique consecutive states (deduplicating repeated writes of the
    same state) and asserts they match expected_states exactly.
    """
    writes = get_ha_state_write_sequence(cmd, n=n)
    actual = []
    for _, value in writes:
        if not actual or actual[-1] != value:
            actual.append(value)
    # Filter to only states present in expected list to ignore pre-existing writes
    relevant = [s for s in actual if s in expected_states]
    # Take the last len(expected_states) transitions
    if len(relevant) > len(expected_states):
        relevant = relevant[-len(expected_states):]
    assert relevant == expected_states, (
        f"Expected HA state transition order {expected_states}, "
        f"got {relevant} (full sequence: {actual})"
    )


def assert_no_state_flapping(cmd: CommandExecutor, window_secs: float = 10, n: int = 50):
    """Assert no rapid state oscillation in the gNMI log.

    Flapping is defined as 3+ unique consecutive state changes within the
    given time window.
    """
    writes = get_ha_state_write_sequence(cmd, n=n)
    if len(writes) < 3:
        return
    # Check sliding windows for rapid changes
    for i in range(len(writes) - 2):
        ts_start = writes[i][0]
        ts_end = writes[i + 2][0]
        states = [writes[i][1], writes[i + 1][1], writes[i + 2][1]]
        # Only flag if all 3 states are different (oscillation)
        if len(set(states)) >= 3:
            # Parse timestamps if possible
            try:
                from datetime import datetime
                t0 = datetime.fromisoformat(ts_start.replace("Z", "+00:00"))
                t1 = datetime.fromisoformat(ts_end.replace("Z", "+00:00"))
                delta = (t1 - t0).total_seconds()
                if delta < window_secs:
                    assert False, (
                        f"State flapping detected: {states} within {delta:.1f}s "
                        f"(threshold: {window_secs}s)"
                    )
            except (ValueError, ImportError):
                pass
