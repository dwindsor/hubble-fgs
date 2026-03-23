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
            ha_status = cmd.agw_show_ha()
            for line in ha_status.splitlines():
                if "HA State:" in line and "ha-ready" in line:
                    return True
        except Exception:
            pass
        time.sleep(3)
    return False


def poll_ha_state(cmd: CommandExecutor, expected_state: str, timeout: int = 45) -> bool:
    """Poll show_ha until the HA State line contains expected_state."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ha_status = cmd.agw_show_ha()
            for line in ha_status.splitlines():
                if "HA State:" in line and expected_state in line:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def get_peer_member_info(cmd: CommandExecutor, peer_ip: str) -> dict:
    """Return the member_info dict for peer_ip, or {} if absent."""
    try:
        peers_json = cmd.agw_gnmi_ha_peers_json()
        peer = peers_json.get("peers", {}).get(peer_ip, {})
        return peer.get("member_info") or {}
    except Exception:
        return {}


def poll_peer_lb_mode(cmd: CommandExecutor, peer_ip: str, timeout: int = 45) -> str:
    """Poll until peer member_info.lb_mode is a non-empty string; return it."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        lb_mode = get_peer_member_info(cmd, peer_ip).get("lb_mode", "")
        if lb_mode:
            return lb_mode
        time.sleep(2)
    return ""


def poll_peer_compatible(cmd: CommandExecutor, peer_ip: str, expected: bool, timeout: int = 45) -> bool:
    """Poll until peer_compatible matches expected value."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            peers_json = cmd.agw_gnmi_ha_peers_json()
            peer = peers_json.get("peers", {}).get(peer_ip, {})
            member_criteria = peer.get("member_criteria", {})
            if member_criteria.get("peer_compatible") is expected:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def get_peer_lb_mode(cmd: CommandExecutor, peer_ip: str) -> str:
    """Get the lb_mode from peer member_info."""
    peers_json = cmd.agw_gnmi_ha_peers_json()
    peer = peers_json.get("peers", {}).get(peer_ip, {})
    return peer.get("member_info", {}).get("lb_mode", "")
