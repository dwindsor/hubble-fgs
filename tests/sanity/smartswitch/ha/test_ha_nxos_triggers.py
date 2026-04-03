#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA NXOS Trigger tests.

Tests for NX-OS managed state changes that trigger HA transitions:
  - out-of-service / in-service
  - HA config deletion (adminState, peer)

No in-service maps to (HA-states.md):
  ready / not-ready / ha-unavailable -> standalone

Recovery path (HA-states.md):
  ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
"""

import json
import time

import pytest

from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, poll_ha_state, get_local_ha_state,
    poll_peer_service_ok, assert_no_state_flapping,
    assert_state_transition_order,
)
from helper.gnmi_paths import DEVICE_IN_SERVICE_PATH, HA_ADMIN_STATE_PATH, HA_PEERS_PATH


@pytest.mark.ha
@pytest.mark.timeout(240)
class TestNxosTriggers:

    def test_nxos_out_of_service(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Setting out-of-service triggers ha-unavailable -> standalone on peer.

        State Table: ready / not-ready / ha-unavailable -> standalone (peer)
        """
        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"out-of-service"')
        time.sleep(5)

        leader_device = ha_cmd_leader.agw_gnmi_device_show_json()
        assert leader_device.get("in_service_state") == "out-of-service", \
            f"Leader in_service_state={leader_device.get('in_service_state')}, expected out-of-service"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-unavailable", "unavailable"), \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-unavailable"

        follower = get_local_ha_state(ha_cmd_follower)
        assert follower.get("ha_state") in ("ha-not-ready", "standalone"), \
            f"Follower ha_state={follower.get('ha_state')}, expected standalone"

        # Follower's view of leader should reflect service_ok=False
        assert poll_peer_service_ok(ha_cmd_follower, LEADER_IP, expected=False, timeout=30), \
            "Follower did not detect service_ok=False for leader after out-of-service"

    def test_nxos_in_service_recovery(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Restoring in-service recovers through standby path.

        Recovery: ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"out-of-service"')
        time.sleep(5)

        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"in-service"')

        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover to ha-ready after in-service restore"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=60), \
            "Follower did not recover to ha-ready"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") == "ha-ready", \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-ready"

    def test_nxos_config_delete_admin_state(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Deleting HA adminState config should disable HA -> standalone."""
        ha_cmd_leader.agw_mock_gnmi_delete(HA_ADMIN_STATE_PATH)
        time.sleep(5)

        info = ha_cmd_leader.agw_ha_info_json()
        assert info.get("admin_state") in ("disabled", ""), \
            f"Leader admin_state={info.get('admin_state')}, expected disabled after delete"

    def test_nxos_config_delete_peer(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Deleting peer config should result in no-ha -> standalone.

        State Table: ready/not-ready / unknown / no-ha -> standalone
        """
        ha_cmd_leader.agw_mock_gnmi_delete(HA_PEERS_PATH)
        time.sleep(5)

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-not-ready", "standalone", "no-ha"), \
            f"Leader ha_state={leader.get('ha_state')}, expected standalone/no-ha"

    def test_nxos_gnmi_write_order(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """gNMI writes during out-of-service/in-service should not flap.

        Expected agentHaState sequence (HA-states.md MO Translation):
          ha-ready -> ha-unavailable -> ha-switchover -> ha-ready

        Out-of-service is a local service failure. Recovery goes through
        active/standby (syncing, standby side) -> ha-switchover, then
        active/active -> ha-ready.
        """
        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"out-of-service"')
        time.sleep(5)
        ha_cmd_leader.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"in-service"')
        assert wait_for_ha_ready(ha_cmd_leader, timeout=60), \
            "Leader did not recover"

        assert_no_state_flapping(ha_cmd_leader)
        assert_state_transition_order(
            ha_cmd_leader,
            ["ha-ready", "ha-unavailable", "ha-switchover", "ha-ready"],
        )

    def test_nxos_peer_list_update_sets_ip_config_criterion(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Setting peer list via HA_PEERS_PATH with ipConfigState=success should set peer_ip_config criterion.

        Tests that the bare JSON array format [{"ipAddr":"...","ipConfigState":"success"}]
        is correctly parsed and sets the peer_ip_config adjacency criterion.
        """
        # Set peer list with ipConfigState=success
        peer_list_json = json.dumps([{"ipAddr": FOLLOWER_IP, "ipConfigState": "success"}])
        ha_cmd_leader.agw_mock_gnmi_set(HA_PEERS_PATH, f'"{peer_list_json}"')
        time.sleep(3)

        # Verify peer_ip_config adjacency criterion is true
        peers_data = ha_cmd_leader.agw_ha_peers_show_json()
        peers = peers_data.get("peers", {})
        assert FOLLOWER_IP in peers, \
            f"Follower {FOLLOWER_IP} not found in leader's peers after gNMI update"

        peer = peers[FOLLOWER_IP]
        adjacency_criteria = peer.get("adjacency_criteria", {})
        assert adjacency_criteria.get("peer_ip_config") is True, \
            f"Expected peer_ip_config=true after ipConfigState=success, got {adjacency_criteria.get('peer_ip_config')}"

    def test_nxos_peer_list_update_ipconfig_failed(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Setting peer list with ipConfigState=failed should set peer_ip_config to false."""
        # Set peer list with ipConfigState=failed
        peer_list_json = json.dumps([{"ipAddr": FOLLOWER_IP, "ipConfigState": "failed"}])
        ha_cmd_leader.agw_mock_gnmi_set(HA_PEERS_PATH, f'"{peer_list_json}"')
        time.sleep(3)

        # Verify peer_ip_config adjacency criterion is false
        peers_data = ha_cmd_leader.agw_ha_peers_show_json()
        peers = peers_data.get("peers", {})
        assert FOLLOWER_IP in peers, \
            f"Follower {FOLLOWER_IP} not found in leader's peers after gNMI update"

        peer = peers[FOLLOWER_IP]
        adjacency_criteria = peer.get("adjacency_criteria", {})
        assert adjacency_criteria.get("peer_ip_config") is False, \
            f"Expected peer_ip_config=false after ipConfigState=failed, got {adjacency_criteria.get('peer_ip_config')}"
