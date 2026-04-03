#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA Connectivity tests.

Tests for peer disconnect/reconnect using container stop/start (realistic)
and debug commands (deterministic).

Disconnect maps to (HA-states.md):
  ready/not-ready / unknown / no-ha -> standalone

Reconnect recovery path (HA-states.md "SW2 Reload With Peer"):
  no-ha -> ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
"""

import logging
import time

import pytest

from helper.ha_helpers import (
    LEADER_IP, FOLLOWER_IP,
    wait_for_ha_ready, get_local_ha_state,
    assert_no_state_flapping,
)
from helper.gnmi_paths import HA_ADMIN_STATE_PATH, HA_IP_PATH, HA_SWITCH_STATE_PATH

logger = logging.getLogger(__name__)


@pytest.mark.ha
@pytest.mark.timeout(300)
class TestConnectivity:

    def _stop_container(self, cmd):
        """Stop the AGW container managed by cmd (idempotent)."""
        container = cmd._get_agw_container()
        container.reload()
        if container.status == "running":
            container.stop(timeout=5)

    def _start_and_reseed(self, cmd, ha_ip):
        """Start container, wait for health, and re-seed gNMI + HA config.

        After a container restart the AGW process needs time to initialize
        and the mock gNMI state is lost, so we must re-seed.
        """
        container = cmd._get_agw_container()
        container.start()
        cmd._agw_container = None
        # Wait for AGW to be ready
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                cmd.agw_health()
                break
            except Exception:
                time.sleep(2)
        # Re-seed gNMI and enable HA
        from pathlib import Path
        gnmi_file = Path(__file__).parent.parent / "testdata" / "gnmi" / "default_gnmi.json"
        try:
            cmd.agw_mock_gnmi_set_file(str(gnmi_file))
            cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"enabled"')
            cmd.agw_mock_gnmi_set(HA_SWITCH_STATE_PATH, '"ha-ready"')
            cmd.agw_mock_gnmi_set(HA_IP_PATH, f'"{ha_ip}"')
        except Exception as e:
            logger.warning(f"Failed to re-seed gNMI after container restart: {e}")
        time.sleep(3)

    def test_conn_peer_disconnect(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Stopping follower causes leader to go standalone.

        State Table: ready/not-ready / unknown / no-ha -> standalone
        """
        self._stop_container(ha_cmd_follower)
        try:
            time.sleep(10)

            leader = get_local_ha_state(ha_cmd_leader)
            assert leader.get("ha_state") in ("ha-not-ready", "standalone", "no-ha"), \
                f"Leader ha_state={leader.get('ha_state')}, expected standalone/no-ha"
        finally:
            # Always restart follower so subsequent tests have a running container
            self._start_and_reseed(ha_cmd_follower, FOLLOWER_IP)

    def test_conn_peer_reconnect(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Reconnecting follower recovers through standby path.

        Recovery: no-ha -> ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        self._stop_container(ha_cmd_follower)
        time.sleep(10)

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-not-ready", "standalone", "no-ha"), \
            f"Leader ha_state={leader.get('ha_state')}, expected standalone before reconnect"

        self._start_and_reseed(ha_cmd_follower, FOLLOWER_IP)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=90), \
            "Leader did not recover to ha-ready after follower reconnect"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=90), \
            "Follower did not reach ha-ready after restart"

        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") == "ha-ready", \
            f"Leader ha_state={leader.get('ha_state')}, expected ha-ready"

    def test_conn_splitbrain_merge(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Splitbrain merge after both restart.

        HA-states.md "Merge After Splitbrain":
          no-ha -> ha-fail (active/standby) -> ha-degraded (active/standby) -> ha-ok (active/active)
        """
        self._stop_container(ha_cmd_follower)
        self._stop_container(ha_cmd_leader)
        time.sleep(5)

        self._start_and_reseed(ha_cmd_leader, LEADER_IP)
        self._start_and_reseed(ha_cmd_follower, FOLLOWER_IP)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=90), \
            "Leader did not reach ha-ready after splitbrain merge"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=90), \
            "Follower did not reach ha-ready after splitbrain merge"

        for name, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
            local = get_local_ha_state(cmd)
            assert local.get("ha_state") == "ha-ready", \
                f"{name}: ha_state={local.get('ha_state')}, expected ha-ready"

    def test_conn_single_node_startup(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """Single node startup without peer stays standalone.

        HA-states.md "SW1 Reload Without Peer":
          not-ready -> ready, peer unknown, no-ha -> standalone
        """
        self._stop_container(ha_cmd_follower)
        time.sleep(5)

        # Restart leader (simulates reload without peer)
        self._stop_container(ha_cmd_leader)
        time.sleep(3)
        self._start_and_reseed(ha_cmd_leader, LEADER_IP)

        # Leader should be standalone with no peer
        time.sleep(5)
        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-not-ready", "standalone", "no-ha"), \
            f"Leader ha_state={leader.get('ha_state')}, expected standalone/no-ha"

        # Wait a bit and confirm it stays standalone (doesn't transition)
        time.sleep(10)
        leader = get_local_ha_state(ha_cmd_leader)
        assert leader.get("ha_state") in ("ha-not-ready", "standalone", "no-ha"), \
            f"Leader ha_state={leader.get('ha_state')}, should remain standalone without peer"

        # Restart follower so cleanup can proceed
        self._start_and_reseed(ha_cmd_follower, FOLLOWER_IP)

    def test_conn_gnmi_no_flapping(self, ha_cmd_leader, ha_cmd_follower, wait_for_ha_ready_both, reset_ha_state_class):
        """gNMI state writes should not flap during disconnect/reconnect."""
        self._stop_container(ha_cmd_follower)
        time.sleep(10)
        self._start_and_reseed(ha_cmd_follower, FOLLOWER_IP)

        assert wait_for_ha_ready(ha_cmd_leader, timeout=90), \
            "Leader did not recover"
        assert wait_for_ha_ready(ha_cmd_follower, timeout=90), \
            "Follower did not recover"

        assert_no_state_flapping(ha_cmd_leader)
        assert_no_state_flapping(ha_cmd_follower)
