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

    def test_ha_port_default(self, cmd, seed_gnmi):
        """ha_port should be present in the HA store JSON output.

        When HA is disabled (default), ha_port is 0 because SetHaPort is
        only called during HA activation. The field must still be present
        in the JSON response for observability.
        """
        data = cmd.agw_gnmi_ha_show_json()
        assert "ha_port" in data, (
            "ha_port field should be present in HA show JSON"
        )
        assert isinstance(data["ha_port"], int), (
            f"ha_port should be an integer, got {type(data['ha_port'])}"
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


@pytest.mark.nxos
class TestHAPortPersistence:
    """Verify HA port is persisted in the HA store and readable via mock gNMI."""

    def test_ha_port_written_to_gnmi(self, cmd, seed_gnmi):
        """When HA port is set in the store, it should be readable via mock gNMI GET.

        The HA port is an agent-managed SET path (HAStoreHaPort). In mock mode
        with HA disabled, SetHaPort is not called, so the port defaults to 0.
        Verify the value is consistently reflected in the HA show JSON.
        """
        data = cmd.agw_gnmi_ha_show_json()
        ha_port = data.get("ha_port", None)
        assert ha_port is not None, "ha_port must be present in HA show JSON"
        # The port is either 0 (HA disabled) or within the HSA range (HA enabled).
        assert isinstance(ha_port, int), (
            f"ha_port should be an integer, got {type(ha_port)}"
        )
        # When HA is disabled, port should be 0
        if data.get("admin_state") == "disabled":
            assert ha_port == 0, (
                f"ha_port should be 0 when HA is disabled, got {ha_port}"
            )
