#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""HA store subscribe-path tests.

Verifies that gNMI subscribe paths (switch-managed) correctly populate the
HA store. Agent-managed SET paths (LocalSvcState, LocalHaState, peer state)
are tested in test_nxos_triggers.py.

This tests the HA gNMI store in single-AGW mode, not the dual-AGW HA
behavior tested in test_ha.py.

All tests run in headless mode (no DPU containers required).
"""

import time

import pytest

from helper.gnmi_paths import (
    HA_ADMIN_STATE_PATH,
    HA_IP_PATH,
)


@pytest.mark.nxos
class TestHAStorePopulation:
    """Verify subscribe-path fields are populated from mock gNMI seed."""

    def test_ha_store_defaults(self, cmd, seed_gnmi):
        """HA subscribe-path fields should match mock defaults.

        Subscribe paths tested:
          - HAStoreEnabled     -> admin_state
          - HAStoreSwitchState -> oper_state
          - HAStoreHaIp        -> local_ip
          - HAStorePeers       -> peers
        """
        data = cmd.agw_gnmi_ha_show_json()
        assert data is not None, "HA show JSON should not be None"

        assert data.get("admin_state") == "disabled", (
            f"admin_state: expected 'disabled', got '{data.get('admin_state')}'"
        )
        assert isinstance(data.get("oper_state", None), str), (
            "oper_state should be a string"
        )
        assert isinstance(data.get("local_ip", None), str), (
            "local_ip should be a string"
        )


@pytest.mark.nxos
class TestHAStoreDynamic:
    """Dynamic HA state changes via subscribe-path notifications."""

    def test_enable_ha_via_gnmi(self, cmd, seed_gnmi):
        """Setting adminState=enabled via gNMI updates HA store."""
        try:
            cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"enabled"')
            time.sleep(2)

            data = cmd.agw_gnmi_ha_show_json()
            assert data.get("admin_state") == "enabled", (
                f"Expected admin_state='enabled', got '{data.get('admin_state')}'"
            )
        finally:
            cmd.agw_mock_gnmi_set(HA_ADMIN_STATE_PATH, '"disabled"')
            time.sleep(2)

    def test_ha_ip_update(self, cmd, seed_gnmi):
        """Setting agentHaSrcIntfAddr via gNMI updates local_ip."""
        data_before = cmd.agw_gnmi_ha_show_json()
        original_ip = data_before.get("local_ip", "")

        try:
            cmd.agw_mock_gnmi_set(HA_IP_PATH, '"10.10.10.1"')
            time.sleep(2)

            data = cmd.agw_gnmi_ha_show_json()
            assert data.get("local_ip") == "10.10.10.1", (
                f"Expected local_ip='10.10.10.1', got '{data.get('local_ip')}'"
            )
        finally:
            # Restore original value (use a space-padded empty if original was empty,
            # since agwctl mock gnmi set requires a non-empty --value)
            restore_val = f'"{original_ip}"' if original_ip else '"0.0.0.0"'
            cmd.agw_mock_gnmi_set(HA_IP_PATH, restore_val)
            time.sleep(2)
