#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""Device store subscribe-path tests.

Verifies that gNMI subscribe paths (switch-managed) correctly populate the
device store. Agent-managed SET paths (connection_status, admission_status,
system_state, etc.) are tested in test_nxos_triggers.py.

All tests run in headless mode (no DPU containers required).
"""

import time

import pytest

from helper.gnmi_paths import LB_MODE_PATH


@pytest.mark.nxos
class TestDeviceStorePopulation:
    """Verify all subscribe-path fields are populated from mock gNMI seed."""

    def test_device_store_population(self, cmd, seed_gnmi):
        """All subscribe-path device fields should match mock defaults.

        Subscribe paths tested:
          - DeviceStoreSerialNumber  -> serial_number
          - DeviceStoreModel         -> model
          - DeviceStoreSupervisorType -> software_version
          - DeviceStoreServiceIP     -> service_ip
          - DeviceStoreInService     -> in_service, in_service_state
          - DeviceStoreLoadBalancingMode -> lb_mode
          - CPAVersion (agent build version) -> cpa_version
        """
        data = cmd.agw_gnmi_device_show_json()
        assert data is not None, "Device show JSON should not be None"

        assert data.get("serial_number") == "MOCK-SERIAL-001", (
            f"serial_number: expected 'MOCK-SERIAL-001', got '{data.get('serial_number')}'"
        )
        assert data.get("model") == "N9K-MOCK", (
            f"model: expected 'N9K-MOCK', got '{data.get('model')}'"
        )
        assert data.get("software_version") == "10.5(1)", (
            f"software_version: expected '10.5(1)', got '{data.get('software_version')}'"
        )
        assert data.get("service_ip") == "10.0.0.1", (
            f"service_ip: expected '10.0.0.1', got '{data.get('service_ip')}'"
        )
        assert data.get("in_service") is True, (
            f"in_service: expected True, got {data.get('in_service')}"
        )
        assert data.get("in_service_state") == "in-service", (
            f"in_service_state: expected 'in-service', got '{data.get('in_service_state')}'"
        )
        assert data.get("lb_mode") == "symmetric_hash", (
            f"lb_mode: expected 'symmetric_hash', got '{data.get('lb_mode')}'"
        )
        assert data.get("cpa_version"), (
            f"cpa_version should be non-empty (agent build version), got '{data.get('cpa_version')}'"
        )


@pytest.mark.nxos
class TestDeviceLoadBalancing:
    """LoadBalancingMode subscribe path: dynamic changes via gNMI."""

    def test_lb_mode_change_via_gnmi(self, cmd, seed_gnmi):
        """Changing LB mode via gNMI updates device store."""
        data_before = cmd.agw_gnmi_device_show_json()
        original_mode = data_before.get("lb_mode", "symmetric_hash")
        try:
            cmd.agw_mock_gnmi_set(LB_MODE_PATH, '"dpu_pinning"')
            time.sleep(2)

            data = cmd.agw_gnmi_device_show_json()
            assert data.get("lb_mode") == "dpu_pinning", (
                f"Expected 'dpu_pinning' after gNMI set, got '{data.get('lb_mode')}'"
            )
        finally:
            cmd.agw_mock_gnmi_set(LB_MODE_PATH, f'"{original_mode}"')
            time.sleep(2)
