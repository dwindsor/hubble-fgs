#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

from enum import Enum


class AGWCTL(Enum):
    """AGW control commands
    
    Commands that work in test environment (no NXOS):
    - HEALTH, SHOW_DPU, SHOW_LOG, SHOW_TOKENS
    - POLICIES_* (all policy commands)
    
    Commands that require NXOS (will fail in test env):
    - SHOW_STATUS, SHOW_VRF, SHOW_TECH (includes status)
    """
    HEALTH = "health"
    SHOW_STATUS = "show_status"  # Requires NXOS
    SHOW_DPU = "show_dpu"
    SHOW_VRF = "show_vrf"  # Requires NXOS
    SHOW_LOG = "show_log"
    POLICIES_ADD = "policies add -f {}"
    POLICIES_SHOW = "policies show"
    POLICIES_SHOW_FILTER = "policies show --filter {}"
    POLICIES_REMOVE = "policies remove -f {}"
    POLICIES_CLEAR = "policies clear"
    PING_FWA = "ping_fwa {}"
    SHOW_TOKENS = "show_tokens"
    SHOW_TECH = "show_tech"  # Requires NXOS


class FWACTL(Enum):
    """FWA control commands
    
    Note: All dataplane commands require the dataplane backend service
    (/var/run/pds_svc_server_dp_app.sock) which is not available in
    test environment without actual hardware.
    """
    LOADCONFIG = "loadconfig {}"
    DATAPLANE_GET_FLOWS = "dataplane get flows"  # Requires dataplane backend
    DATAPLANE_CLEAR_FLOWS = "dataplane clear flows"  # Requires dataplane backend
    DATAPLANE_GET_PORTSTATS = "dataplane get portstats"  # Requires dataplane backend
    DATAPLANE_POL_ENABLE = "dataplane pol enable"  # Requires dataplane backend
    DATAPLANE_POL_DISABLE = "dataplane pol disable"  # Requires dataplane backend

class DPCTL(Enum):
    """SIM container dpctl commands
    
    Commands for interacting with the dataplane simulator.
    """
    POLICY_UPDATE = 'dpctl hs policies update -f /data/{}'
    POLICY_CLEAR = 'dpctl hs policies clear'
    CLEAR_FLOWS = 'dpctl clear flow'
    SHOW_FLOWS = 'dpctl show flow'
    POLICIES_SHOW = 'dpctl hs policies show'
    DISABLE_POLICIER = 'dpctl hs pol disable'
    DROP_STATISTICS = "dpctl show pipeline statistics drop"
    DROP_STATISTICS_CLEAR = "dpctl clear pipeline statistics drop"
    APPLY_SYSLOG = "dpctl hs fwa_message -f {}"
    VRF_MAP_SHOW = "dpctl hs vrf show-map"
    VRF_ADD = "dpctl hs vrf add {}"
    VRF_DEL = "dpctl hs vrf del {}"
    ENABLE_INTER_VRF = "dpctl hs vrf enable"
    DISABLE_INTER_VRF = "dpctl hs vrf disable"
