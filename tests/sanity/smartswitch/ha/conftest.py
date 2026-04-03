#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import json
import time
import logging
from pathlib import Path

import pytest

from config.testing_config import TestingConfig
from helper.command_executor import CommandExecutor
from helper.ha_helpers import LEADER_IP, FOLLOWER_IP, wait_for_ha_ready
from helper.gnmi_paths import (
    HA_ADMIN_STATE_PATH,
    HA_IP_PATH,
    HA_PEERS_PATH,
    HA_SWITCH_STATE_PATH,
)

logger = logging.getLogger(__name__)

TESTDATA_DIR = Path(__file__).parent.parent / "testdata" / "gnmi"


@pytest.fixture(scope="session")
def ha_cmd_leader(config) -> CommandExecutor:
    cfg = TestingConfig()
    cfg.agw_container_name = config.agw_leader_name
    executor = CommandExecutor(cfg)
    try:
        executor.agw_health()
    except Exception:
        pytest.skip("agw-leader not available")
    return executor


@pytest.fixture(scope="session")
def ha_cmd_follower(config) -> CommandExecutor:
    cfg = TestingConfig()
    cfg.agw_container_name = config.agw_follower_name
    executor = CommandExecutor(cfg)
    try:
        executor.agw_health()
    except Exception:
        pytest.skip("agw-follower not available")
    return executor


@pytest.fixture(scope="session", autouse=True)
def skip_ha_if_unavailable(config):
    """Auto-skip all tests in ha/ when HA containers are not running."""
    for name in (config.agw_leader_name, config.agw_follower_name):
        cfg = TestingConfig()
        cfg.agw_container_name = name
        try:
            CommandExecutor(cfg).agw_health()
        except Exception:
            pytest.skip(f"HA container '{name}' not available — run 'make launch-ha-agw' first")


def _seed_gnmi_and_enable_ha(cmd, gnmi_file, ha_ip, peer_ip):
    """Seed mock gNMI from file, then enable HA with the given source IP and peer."""
    if not gnmi_file.exists():
        logger.warning(f"gNMI seed file not found: {gnmi_file}")
        return
    try:
        output = cmd.agw_mock_gnmi_set_file(str(gnmi_file))
        logger.info(f"Seeded mock gNMI from {gnmi_file}: {output}")
    except Exception as e:
        logger.warning(f"Failed to seed mock gNMI: {e}")
        return
    # Enable HA and set source IP via gNMI SET
    try:
        cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"enabled"')
        cmd.agw_mock_gnmi_set(HA_SWITCH_STATE_PATH, '"ha-ready"')
        cmd.agw_mock_gnmi_set(HA_IP_PATH, f'"{ha_ip}"')
        # Seed peer list using real NX-OS array format
        peer_list_json = json.dumps([{"ipAddr": peer_ip, "ipConfigState": "success"}])
        cmd.agw_mock_gnmi_set(HA_PEERS_PATH, f'"{peer_list_json}"')
        logger.info(f"Enabled HA with source IP {ha_ip} and peer {peer_ip}")
    except Exception as e:
        logger.warning(f"Failed to enable HA: {e}")
    time.sleep(3)


@pytest.fixture(scope="session")
def seed_gnmi_leader(ha_cmd_leader):
    """Seed the mock gNMI handler on the leader and enable HA."""
    gnmi_file = TESTDATA_DIR / "default_gnmi_skip_dpu.json"
    _seed_gnmi_and_enable_ha(ha_cmd_leader, gnmi_file, LEADER_IP, FOLLOWER_IP)


@pytest.fixture(scope="session")
def seed_gnmi_follower(ha_cmd_follower):
    """Seed the mock gNMI handler on the follower and enable HA."""
    gnmi_file = TESTDATA_DIR / "default_gnmi_skip_dpu.json"
    _seed_gnmi_and_enable_ha(ha_cmd_follower, gnmi_file, FOLLOWER_IP, LEADER_IP)


@pytest.fixture(scope="session")
def wait_for_ha_ready_both(seed_gnmi_leader, seed_gnmi_follower, ha_cmd_leader, ha_cmd_follower):
    """Seed gNMI on both nodes and wait for both to reach ha-ready.

    Session-scoped: runs once per test session. Most test files should
    depend on this fixture to ensure a stable baseline.
    """
    assert wait_for_ha_ready(ha_cmd_leader, timeout=90), \
        "Leader did not reach ha-ready within 90s"
    assert wait_for_ha_ready(ha_cmd_follower, timeout=90), \
        "Follower did not reach ha-ready within 90s"


def _restore_ha_baseline(ha_cmd_leader, ha_cmd_follower):
    """Shared teardown logic: restore both nodes to baseline.

    - Clears debug overrides on both nodes
    - Ensures both containers are running
    - Restores in-service state
    - Waits for ha-ready on both (short timeout — callers gate readiness)
    """
    for cmd, ha_ip, peer_ip in [
        (ha_cmd_leader, LEADER_IP, FOLLOWER_IP),
        (ha_cmd_follower, FOLLOWER_IP, LEADER_IP),
    ]:
        # Ensure container is running
        try:
            container = cmd._get_agw_container()
            container.reload()
            if container.status != "running":
                container.start()
                cmd._agw_container = None
                # Wait for AGW to be ready after restart
                deadline = time.time() + 30
                while time.time() < deadline:
                    try:
                        cmd.agw_health()
                        break
                    except Exception:
                        time.sleep(2)
                else:
                    logger.warning("Container did not become healthy within 30s during baseline restore")
                # Re-seed gNMI after restart (mock state lost)
                gnmi_file = TESTDATA_DIR / "default_gnmi_skip_dpu.json"
                if gnmi_file.exists():
                    try:
                        cmd.agw_mock_gnmi_set_file(str(gnmi_file))
                    except Exception as e:
                        logger.warning(f"Failed to re-seed gNMI after restart: {e}")
        except Exception as e:
            logger.warning(f"Failed to ensure container running during baseline restore: {e}")
        # Clear debug overrides
        try:
            cmd.agw_ha_debug_ok()
        except Exception:
            pass
        # Re-enable HA and restore in-service
        try:
            cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"enabled"')
            cmd.agw_mock_gnmi_set(HA_SWITCH_STATE_PATH, '"ha-ready"')
            cmd.agw_mock_gnmi_set(HA_IP_PATH, f'"{ha_ip}"')
            # Re-seed peer list
            peer_list_json = json.dumps([{"ipAddr": peer_ip, "ipConfigState": "success"}])
            cmd.agw_mock_gnmi_set(HA_PEERS_PATH, f'"{peer_list_json}"')
            from helper.gnmi_paths import DEVICE_IN_SERVICE_PATH
            cmd.agw_mock_gnmi_set(DEVICE_IN_SERVICE_PATH, '"in-service"')
        except Exception:
            pass
    time.sleep(3)
    if not wait_for_ha_ready(ha_cmd_leader, timeout=30):
        logger.warning("Leader did not reach ha-ready during baseline restore")
    if not wait_for_ha_ready(ha_cmd_follower, timeout=30):
        logger.warning("Follower did not reach ha-ready during baseline restore")


@pytest.fixture
def reset_ha_state(ha_cmd_leader, ha_cmd_follower):
    """Restore both nodes to baseline after each destructive test.

    Use reset_ha_state_class instead when an entire class of related tests
    can share a single teardown (e.g. fail/recover pairs).
    """
    yield
    _restore_ha_baseline(ha_cmd_leader, ha_cmd_follower)


@pytest.fixture(scope="class")
def reset_ha_state_class(ha_cmd_leader, ha_cmd_follower):
    """Restore both nodes to baseline once after all tests in a class.

    Runs teardown only after the last test in the class completes,
    eliminating redundant resets between related fail/recover tests.
    Tests within the class run in definition order; each recovery test
    should be self-contained (trigger its own failure before recovering).
    """
    yield
    _restore_ha_baseline(ha_cmd_leader, ha_cmd_follower)


@pytest.fixture
def gnmi_log_marker(ha_cmd_leader, ha_cmd_follower):
    """Capture the current gNMI log length before a test.

    Returns a dict with leader/follower log counts so post-test assertions
    can scope to "writes during this test" by using -n offset.
    """
    counts = {}
    for name, cmd in [("leader", ha_cmd_leader), ("follower", ha_cmd_follower)]:
        try:
            entries = cmd.agw_mock_gnmi_log_json(n=0)
            counts[name] = len(entries)
        except Exception:
            counts[name] = 0
    return counts
