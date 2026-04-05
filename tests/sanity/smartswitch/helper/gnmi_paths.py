#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

"""Shared gNMI path constants, builders, and CRUD helpers for integration tests.

All path constants correspond to definitions in pkg/nxos/gnmi/paths/paths.go.
Paths are grouped by store and by direction (subscribe vs agent-managed SET).
"""

import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Device store — subscribe paths (switch-managed)
# ---------------------------------------------------------------------------

TOKEN_PATH = (
    "device:/System/sas-items/volatiledata-items/agent-items/"
    "SasAgentData-list[svcName=hypershield]/connToken"
)

DEVICE_PROXY_SERVER_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/httpsProxySvr"
)

DEVICE_PROXY_PORT_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/httpsProxyPort"
)

DEVICE_SERIAL_PATH = "device:/System/ch-items/spbp-items/spcmn-items/serNum"

DEVICE_MODEL_PATH = "device:/System/ch-items/spbp-items/spcmn-items/pdNum"

DEVICE_SERVICE_IP_PATH = (
    "device:/System/sas-items/state-items/agent-items/"
    "SasAgent-list[svcName=hypershield]/agentSrcIntfAddr"
)

DEVICE_IN_SERVICE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicy-items/operState"
)

DEVICE_SUPERVISOR_TYPE_PATH = (
    "device:/System/ch-items/supslot-items/SupCSlot-list/sup-items/type"
)

LB_MODE_PATH = "device:/System/sas-items/globalpol-items/lbMode"

# ---------------------------------------------------------------------------
# Device store — agent-managed SET paths
# ---------------------------------------------------------------------------

DEVICE_ADMISSION_STATUS_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/admissionStatus"
)

DEVICE_CONNECTION_STATUS_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/connectionStatus"
)

DEVICE_REJECT_REASON_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/rejectReason"
)

DEVICE_CONTROLLER_ENDPOINT_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/controllerEndpoint"
)

DEVICE_CONTROLLER_PORT_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/controllerPort"
)

DEVICE_CONTROLLER_VERSION_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/scontroller-items/ext-items/version"
)

SYSTEM_STATE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/sagent-items/ext-items/systemState"
)

# ---------------------------------------------------------------------------
# DPU store — subscribe paths (switch-managed)
# ---------------------------------------------------------------------------

DPU_NUM_DPUS_PATH = "device:/System/sas-items/dpu-items/ext-items/numDpus"
DPU_INIT_STATE_PATH = "device:/System/sas-items/dpu-items/ext-items/initState"


def dpu_ip_path(module_num):
    """gNMI path for a DPU's IP address (subscribe)."""
    return (
        f"device:/System/sas-items/dpu-items/inst-items/"
        f"Inst-list[moduleNum={module_num}]/ext-items/ip"
    )


def dpu_state_path(module_num):
    """gNMI path for a DPU's state (subscribe)."""
    return (
        f"device:/System/sas-items/dpu-items/inst-items/"
        f"Inst-list[moduleNum={module_num}]/ext-items/state"
    )


def dpu_version_path(module_num):
    """gNMI path for a DPU's firmware version (subscribe)."""
    return (
        f"device:/System/sas-items/dpu-items/inst-items/"
        f"Inst-list[moduleNum={module_num}]/ext-items/mainFwVer"
    )


# ---------------------------------------------------------------------------
# DPU store — agent-managed SET paths
# ---------------------------------------------------------------------------

def dpu_tcp_ports_path(module_num):
    """gNMI path for a DPU's TCP port range (agent SET)."""
    return (
        f"device:/System/sas-items/dpu-items/inst-items/"
        f"Inst-list[moduleNum={module_num}]/ext-items/tcpCpPortRange"
    )


def dpu_udp_ports_path(module_num):
    """gNMI path for a DPU's UDP port range (agent SET)."""
    return (
        f"device:/System/sas-items/dpu-items/inst-items/"
        f"Inst-list[moduleNum={module_num}]/ext-items/udpCpPortRange"
    )


# ---------------------------------------------------------------------------
# HA store — subscribe paths (switch-managed)
# ---------------------------------------------------------------------------

HA_ADMIN_STATE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/adminState"
)

HA_SWITCH_STATE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/nxHaOperState"
)

HA_PEERS_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list"
)


def ha_peer_ip_path(peer_ip):
    """Build per-peer gNMI path for the ipAddr leaf (creates the peer)."""
    return f"{HA_PEERS_PATH}[ipAddr={peer_ip}]/ipAddr"


def ha_peer_ip_config_state_path(peer_ip):
    """Build per-peer gNMI path for ipConfigState (gates peer connection)."""
    return f"{HA_PEERS_PATH}[ipAddr={peer_ip}]/ipConfigState"


HA_IP_PATH = (
    "device:/System/sas-items/state-items/agent-items/"
    "SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr"
)

# ---------------------------------------------------------------------------
# HA store — agent-managed SET paths
# ---------------------------------------------------------------------------

HA_PORT_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaPort"
)

HA_LOCAL_SVC_STATE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/ext-items/localSvcState"
)

HA_LOCAL_SVC_STATE_REASON_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/ext-items/localSvcStateReason"
)

HA_LOCAL_HA_STATE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaState"
)

HA_LOCAL_HA_STATE_REASON_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/ha-items/ext-items/agentHaStateReason"
)

# ---------------------------------------------------------------------------
# VRF store — subscribe paths (switch-managed)
# ---------------------------------------------------------------------------

# (VRF path builders defined below in "VRF path builders" section)

# ---------------------------------------------------------------------------
# VLAN store — subscribe paths (switch-managed)
# ---------------------------------------------------------------------------

# (VLAN path builders defined below in "VLAN path builders" section)

# ---------------------------------------------------------------------------
# Manager lifecycle paths (subscription-only, DELETE triggers restart)
# ---------------------------------------------------------------------------

SVC_INSTANCE_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list"
)

SVC_FW_POLICY_PATH = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicy-items"
)

# ---------------------------------------------------------------------------
# Service redirect paths (agent-managed SET/DELETE)
# ---------------------------------------------------------------------------

SERVICE_REDIR_SERVICE_ITEMS = "device:/System/serviceredir-items/inst-items/service-items"
SERVICE_REDIR_PMAP_ITEMS = "device:/System/serviceredir-items/inst-items/pmap-items"
SERVICE_REDIR_DOM_ITEMS = "device:/System/serviceredir-items/inst-items/dom-items"
SERVICE_REDIR_BD_ITEMS = "device:/System/serviceredir-items/inst-items/bd-items"

# Aliases used by existing VRF/VLAN redirect tests (without device: prefix)
VRF_SERVICE_ITEMS = "System/serviceredir-items/inst-items/service-items"
VRF_ENFORCEMENT = "System/serviceredir-items/inst-items/dom-items"
VRF_PMAP = "System/serviceredir-items/inst-items/pmap-items"
VLAN_ENFORCEMENT = "System/serviceredir-items/inst-items/bd-items"

# ---------------------------------------------------------------------------
# FW policy state paths (agent-managed SET/DELETE)
# ---------------------------------------------------------------------------

FW_POLICY_STATE_VRF = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/ipvrfstate-items/dom-items"
)

FW_POLICY_STATE_VLAN = (
    "device:/System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/bdstate-items/vlan-items"
)

# Aliases used by existing tests (without device: prefix)
VRF_FW_POLICY = (
    "System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/ipvrfstate-items/dom-items"
)
VLAN_FW_POLICY = (
    "System/sas-items/svc-items/svcinst-items/"
    "SvcInstance-list[name=hypershield]/fwpolicystate-items/bdstate-items/vlan-items"
)

# ---------------------------------------------------------------------------
# ACL redirect paths (agent-managed SET)
# ---------------------------------------------------------------------------

ACL_IPV4_REDIRECT = "device:/System/acl-items/ipv4-items/name-items/ACL-list[name=__dpu_redir]"
ACL_IPV6_REDIRECT = "device:/System/acl-items/ipv6-items/name-items/ACL-list[name=__dpu_ipv6_redir]"


# ---------------------------------------------------------------------------
# VRF path builders
# ---------------------------------------------------------------------------

def vrf_global_path(name):
    """Build the mock gNMI path that triggers a VRF global notification."""
    return f"device:/System/inst-items/Inst-list[name={name}]/name"


def vrf_service_path(name):
    """Build the mock gNMI path that triggers a VRF service notification."""
    return (
        f"device:/System/sas-items/svc-items/svcinst-items/"
        f"SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/"
        f"dom-items/Dom-list[name={name}]/name"
    )


def vrf_affinity_path(name):
    """Build the mock gNMI path that triggers a VRF affinity update."""
    return (
        f"device:/System/sas-items/svc-items/svcinst-items/"
        f"SvcInstance-list[name=hypershield]/fwpolicy-items/ipvrf-items/"
        f"dom-items/Dom-list[name={name}]/affinity"
    )


def vrf_service_endpoint_path(name):
    """Build the specific list-entry path for a VRF service endpoint."""
    return f"device:/{VRF_SERVICE_ITEMS}/Service-list[name=__{name}_dpu_redir]"


def vrf_enforcement_path(name):
    """Build the specific list-entry path for a VRF enforcement binding."""
    return f"device:/{VRF_ENFORCEMENT}/Dom-list[name={name}]"


def vrf_pmap_path(name):
    """Build the specific list-entry path for a VRF policy map."""
    return f"device:/{VRF_PMAP}/PolicyMap-list[name=__{name}_dpu_redir]"


def vrf_fw_policy_path(name):
    """Build the specific list-entry path for a VRF fwPolicyState entry."""
    return f"device:/{VRF_FW_POLICY}/DomState-list[name={name}]"


# ---------------------------------------------------------------------------
# VLAN path builders
# ---------------------------------------------------------------------------

def vlan_global_path(vid):
    """Build the mock gNMI path that triggers a VLAN global notification."""
    return f"device:/System/bd-items/bd-items/BD-list[fabEncap={vid}]/fabEncap"


def vlan_service_path(vid):
    """Build the mock gNMI path that triggers a VLAN service notification."""
    return (
        f"device:/System/sas-items/svc-items/svcinst-items/"
        f"SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/"
        f"vlan-items/Vlan-list[vlanId={vid}]/vlanId"
    )


def vlan_affinity_path(vid):
    """Build the mock gNMI path that triggers a VLAN affinity update."""
    return (
        f"device:/System/sas-items/svc-items/svcinst-items/"
        f"SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/"
        f"vlan-items/Vlan-list[vlanId={vid}]/affinity"
    )


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def create_vrf(cmd, name):
    """Create a VRF by setting both global and service paths, then wait."""
    cmd.agw_mock_gnmi_set(vrf_global_path(name), f'"{name}"')
    cmd.agw_mock_gnmi_set(vrf_service_path(name), f'"{name}"')
    time.sleep(2)


def delete_vrf(cmd, name):
    """Delete a VRF by removing both global and service paths."""
    cmd.agw_mock_gnmi_delete(vrf_global_path(name))
    cmd.agw_mock_gnmi_delete(vrf_service_path(name))
    time.sleep(2)


def create_vlan(cmd, vid):
    """Create a VLAN by setting both global and service paths with same ID."""
    cmd.agw_mock_gnmi_set(vlan_global_path(vid), f'"{vid}"')
    cmd.agw_mock_gnmi_set(vlan_service_path(vid), f'"{vid}"')
    time.sleep(2)


def vlan_global_delete_path(vid):
    """Build the list-entry path for a VLAN global delete (no leaf suffix)."""
    return f"device:/System/bd-items/bd-items/BD-list[fabEncap={vid}]"


def vlan_service_delete_path(vid):
    """Build the list-entry path for a VLAN service delete (no leaf suffix)."""
    return (
        f"device:/System/sas-items/svc-items/svcinst-items/"
        f"SvcInstance-list[name=hypershield]/fwpolicy-items/bd-items/"
        f"vlan-items/Vlan-list[vlanId={vid}]"
    )


def delete_vlan(cmd, vid):
    """Delete a VLAN by removing both global and service list-entry paths."""
    cmd.agw_mock_gnmi_delete(vlan_global_delete_path(vid))
    cmd.agw_mock_gnmi_delete(vlan_service_delete_path(vid))
    time.sleep(2)


def find_vrf(cmd, name):
    """Get a VRF entry from vrf show --json by name."""
    data = cmd.agw_gnmi_vrf_show_json()
    return next((v for v in data.get("vrfs", []) if v["name"] == name), None)


def find_vlan(cmd, vid):
    """Get a VLAN entry from vlan show --json by name."""
    data = cmd.agw_gnmi_vlan_show_json()
    return next((v for v in (data.get("vlans") or []) if v["name"] == vid), None)


# ---------------------------------------------------------------------------
# AGW restart helpers
# ---------------------------------------------------------------------------

def wait_for_agw_healthy(cmd, timeout=60, poll=3):
    """Poll agwctl health until it succeeds or *timeout* seconds elapse.

    Returns True if the AGW became healthy within the window.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            cmd.agw_health()
            return True
        except Exception:
            time.sleep(poll)
    return False


def wait_for_agw_unhealthy(cmd, timeout=10, poll=1):
    """Poll agwctl health until it *fails* (AGW process is down).

    Returns True if the AGW became unreachable within the window.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            cmd.agw_health()
            time.sleep(poll)
        except Exception:
            return True
    return False


def reseed_gnmi(cmd):
    """Re-seed mock gNMI after an AGW restart so subsequent tests work."""
    gnmi_file = Path(__file__).parent.parent / "testdata" / "gnmi" / "default_gnmi.json"
    if gnmi_file.exists():
        try:
            cmd.agw_mock_gnmi_set_file(str(gnmi_file))
            time.sleep(3)
        except Exception as exc:
            logger.warning(f"Failed to re-seed gNMI after restart: {exc}")
