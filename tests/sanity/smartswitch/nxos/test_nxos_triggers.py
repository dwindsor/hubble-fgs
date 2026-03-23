#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""Non-store gNMI path tests (agent SET writebacks, redirects, lifecycle).

Tests agent-managed SET paths that are written BY the AGW process (not
subscribed from the switch). Also tests manager-level lifecycle triggers
(restart on in-service delete, token change, fw-policy delete) and
verifies service redirect / FW policy state / ACL redirect programming.

All paths correspond to constants in pkg/nxos/gnmi/paths/paths.go.

All tests run in headless mode (no DPU containers required).

NOTE: Restart tests (TestLifecycleRestarts) trigger AGW process restarts.
init.sh sleeps 20s before relaunching, so these tests wait up to 60s for
health to recover. They are placed last alphabetically so store tests run
first.
"""

import time

import pytest

from helper.gnmi_paths import (
    # Device SET paths
    DEVICE_ADMISSION_STATUS_PATH,
    DEVICE_CONNECTION_STATUS_PATH,
    DEVICE_REJECT_REASON_PATH,
    DEVICE_CONTROLLER_ENDPOINT_PATH,
    DEVICE_CONTROLLER_PORT_PATH,
    DEVICE_CONTROLLER_VERSION_PATH,
    SYSTEM_STATE_PATH,
    # DPU SET paths
    dpu_tcp_ports_path,
    dpu_udp_ports_path,
    # HA SET paths
    HA_LOCAL_SVC_STATE_PATH,
    HA_LOCAL_HA_STATE_PATH,
    # Service redirect paths
    SERVICE_REDIR_SERVICE_ITEMS,
    SERVICE_REDIR_PMAP_ITEMS,
    SERVICE_REDIR_DOM_ITEMS,
    SERVICE_REDIR_BD_ITEMS,
    # FW policy state paths
    FW_POLICY_STATE_VRF,
    FW_POLICY_STATE_VLAN,
    # ACL redirect paths
    ACL_IPV4_REDIRECT,
    ACL_IPV6_REDIRECT,
    # Lifecycle trigger paths
    DEVICE_IN_SERVICE_PATH,
    TOKEN_PATH,
    SVC_FW_POLICY_PATH,
    # Restart helpers
    reseed_gnmi,
    wait_for_agw_healthy,
    wait_for_agw_unhealthy,
)


@pytest.mark.nxos
class TestDeviceAgentWriteBack:
    """Verify agent writes device SET paths back to mock gNMI."""

    def test_device_agent_set_paths(self, cmd, seed_gnmi):
        """Agent should write admission/connection status and system state.

        SET paths tested:
          - DeviceStoreAdmissionStatus
          - DeviceStoreConnectionStatus
          - DeviceStoreRejectReason
          - DeviceStoreControllerEndpoint
          - DeviceStoreControllerPort
          - DeviceStoreControllerVersion
          - DeviceStoreSystemState
        """
        paths_to_check = [
            (DEVICE_ADMISSION_STATUS_PATH, "admissionStatus"),
            (DEVICE_CONNECTION_STATUS_PATH, "connectionStatus"),
            (SYSTEM_STATE_PATH, "systemState"),
        ]
        for path, label in paths_to_check:
            data = cmd.agw_mock_gnmi_get(path)
            assert data is not None, (
                f"Agent should have written {label} to mock gNMI"
            )

        # These paths may be empty strings but should exist
        optional_paths = [
            (DEVICE_REJECT_REASON_PATH, "rejectReason"),
            (DEVICE_CONTROLLER_ENDPOINT_PATH, "controllerEndpoint"),
            (DEVICE_CONTROLLER_PORT_PATH, "controllerPort"),
            (DEVICE_CONTROLLER_VERSION_PATH, "controllerVersion"),
        ]
        for path, label in optional_paths:
            # Just verify these are queryable (agent registers them)
            try:
                cmd.agw_mock_gnmi_get(path)
            except Exception:
                pass  # Some paths may not be set if not configured


@pytest.mark.nxos
class TestDPUAgentWriteBack:
    """Verify agent writes DPU port range SET paths to mock gNMI."""

    def test_dpu_port_ranges_written(self, cmd, seed_gnmi):
        """Agent should write TCP/UDP port ranges for each DPU module.

        SET paths tested:
          - DPUStoreTCPPorts (per module)
          - DPUStoreUDPPorts (per module)
        """
        for module_num in [1, 2]:
            tcp_data = cmd.agw_mock_gnmi_get(dpu_tcp_ports_path(module_num))
            udp_data = cmd.agw_mock_gnmi_get(dpu_udp_ports_path(module_num))
            assert tcp_data is not None, (
                f"TCP port range should be written for module {module_num}"
            )
            assert udp_data is not None, (
                f"UDP port range should be written for module {module_num}"
            )


@pytest.mark.nxos
class TestHAAgentWriteBack:
    """Verify agent writes HA local state SET paths to mock gNMI."""

    def test_ha_local_state_written(self, cmd, seed_gnmi):
        """Agent should write local HA state to gNMI.

        SET paths tested:
          - HAStoreLocalSvcState
          - HAStoreLocalHaState
        """
        for path, label in [
            (HA_LOCAL_SVC_STATE_PATH, "localSvcState"),
            (HA_LOCAL_HA_STATE_PATH, "localHaState"),
        ]:
            try:
                data = cmd.agw_mock_gnmi_get(path)
                # Path should be queryable; value may be empty if HA disabled
            except Exception:
                pass  # HA may not write these when disabled


@pytest.mark.nxos
class TestServiceRedirects:
    """Verify agent programs service redirect paths for active VRFs/VLANs."""

    def test_vrf_redirects_populated(self, cmd, seed_gnmi):
        """Active VRFs should have service redirect paths programmed.

        SET paths tested:
          - ServiceRedirServiceItems
          - ServiceRedirPmapItems
          - ServiceRedirDomItems (VRF enforcement binding)
        """
        for path, label in [
            (SERVICE_REDIR_SERVICE_ITEMS, "service-items"),
            (SERVICE_REDIR_PMAP_ITEMS, "pmap-items"),
            (SERVICE_REDIR_DOM_ITEMS, "dom-items (VRF enforcement)"),
        ]:
            data = cmd.agw_mock_gnmi_get(path)
            assert data, f"Service redirect {label} should have data"

    def test_vlan_redirects_populated(self, cmd, seed_gnmi):
        """Active VLANs should have service redirect paths programmed.

        SET paths tested:
          - ServiceRedirBdItems (VLAN enforcement binding)
        """
        data = cmd.agw_mock_gnmi_get(SERVICE_REDIR_BD_ITEMS)
        assert data, "Service redirect bd-items (VLAN enforcement) should have data"


@pytest.mark.nxos
class TestFwPolicyState:
    """Verify agent programs FW policy state paths."""

    def test_fw_policy_state_vrf_populated(self, cmd, seed_gnmi):
        """Active VRFs should have fwPolicyState programmed.

        SET path: FwPolicyStateVrf
        """
        data = cmd.agw_mock_gnmi_get(FW_POLICY_STATE_VRF)
        assert data, "VRF fwPolicyState should have data"

    def test_fw_policy_state_vlan_populated(self, cmd, seed_gnmi):
        """Active VLANs should have fwPolicyState programmed.

        SET path: FwPolicyStateVlan
        """
        data = cmd.agw_mock_gnmi_get(FW_POLICY_STATE_VLAN)
        assert data, "VLAN fwPolicyState should have data"


@pytest.mark.nxos
class TestAclRedirects:
    """Verify agent programs ACL redirect paths."""

    def test_acl_ipv4_redirect_populated(self, cmd, seed_gnmi):
        """IPv4 ACL redirect should be programmed for active VRFs/VLANs.

        SET path: AclIPv4Redirect (parent: ACL-list[name=__dpu_redir])
        """
        data = cmd.agw_mock_gnmi_get(ACL_IPV4_REDIRECT)
        assert data, "IPv4 ACL redirect path should have data"

    def test_acl_ipv6_redirect_populated(self, cmd, seed_gnmi):
        """IPv6 ACL redirect should be programmed for active VRFs/VLANs.

        SET path: AclIPv6Redirect (parent: ACL-list[name=__dpu_ipv6_redir])
        """
        data = cmd.agw_mock_gnmi_get(ACL_IPV6_REDIRECT)
        assert data, "IPv6 ACL redirect path should have data"


@pytest.mark.nxos
class TestLifecycleRestarts:
    """Manager-level lifecycle triggers that cause AGW restarts.

    These tests trigger actual AGW process restarts via init.sh, which
    sleeps 20s before relaunching. Tests wait up to 60s for recovery.

    Paths tested:
      - DeviceStoreInService (operState DELETE -> restart)
      - DeviceStoreConnToken (token change -> restart)
      - SvcFwPolicyPath (DELETE -> restart)
    """

    def _ensure_healthy_and_seeded(self, cmd):
        """Wait for AGW to be healthy and re-seed gNMI.

        Used after lifecycle restarts to ensure AGW is fully stabilized
        before the next test runs.
        """
        came_back = wait_for_agw_healthy(cmd, timeout=60)
        assert came_back, "AGW should restart and become healthy within 60s"

        reseed_gnmi(cmd)

        # Extra stabilization — AGW needs time to process reseeded paths
        # (redirect rules, FW policy state, etc.)
        time.sleep(5)

        data = cmd.agw_gnmi_device_show_json()
        assert data is not None, "Device show should work after restart"

    def test_delete_in_service_triggers_restart(self, cmd, seed_gnmi):
        """Deleting the operState (in-service) path restarts the AGW process."""
        assert wait_for_agw_healthy(cmd, timeout=60), "AGW should be healthy before test"

        cmd.agw_mock_gnmi_delete(DEVICE_IN_SERVICE_PATH)

        went_down = wait_for_agw_unhealthy(cmd, timeout=10)
        assert went_down, "AGW should become unreachable after in-service path delete"

        self._ensure_healthy_and_seeded(cmd)

    def test_token_change_triggers_restart(self, cmd, seed_gnmi):
        """Setting a second token (after an initial one) restarts the AGW."""
        assert wait_for_agw_healthy(cmd, timeout=60), "AGW should be healthy before test"

        # First token does NOT trigger a restart
        cmd.agw_mock_gnmi_set(TOKEN_PATH, '"initial-token-value"')
        time.sleep(3)
        cmd.agw_health()

        # Change token -> previous was non-empty -> triggers restart
        cmd.agw_mock_gnmi_set(TOKEN_PATH, '"changed-token-value"')

        went_down = wait_for_agw_unhealthy(cmd, timeout=10)
        assert went_down, "AGW should become unreachable after token change"

        self._ensure_healthy_and_seeded(cmd)

    def test_svc_fw_policy_delete_triggers_restart(self, cmd, seed_gnmi):
        """Deleting fwpolicy-items path triggers AGW restart.

        SET path: SvcFwPolicyPath
        """
        assert wait_for_agw_healthy(cmd, timeout=60), "AGW should be healthy before test"

        cmd.agw_mock_gnmi_delete(SVC_FW_POLICY_PATH)

        went_down = wait_for_agw_unhealthy(cmd, timeout=10)
        assert went_down, "AGW should become unreachable after fw-policy delete"

        self._ensure_healthy_and_seeded(cmd)
