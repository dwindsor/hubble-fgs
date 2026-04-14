#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import logging
import random
from typing import List

import allure
import pytest
from scapy.sendrecv import AsyncSniffer

from helper.verification import (
    verify_policy_added_to_agw,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim,
    verify_policies_match_agw_and_dpu,
    send_and_verify_packets,
)
from helper.utils import wait_for_timeout
from helper.constants import AGW_POLICIES_DIR
from helper.packet_generator import generate_packets_from_policy_file, print_generated_packets
from helper.policy_models import VRF_NAME_TO_ID
from parameters.test_params import get_amex_consolidated_policy_params

logger = logging.getLogger(__name__)


@pytest.mark.agw
@pytest.mark.policy
@pytest.mark.amex
@allure.feature("Policy Management")
@allure.story("AMEX Policies")
@pytest.mark.skip(reason="Skipped due to existing bug")
@pytest.mark.parametrize(
    "policy_filename,policy_name,expected_rules",
    get_amex_consolidated_policy_params(),
    ids=[p[1] for p in get_amex_consolidated_policy_params()],
)
def test_amex_egress_consolidated_rules_full(cmd, sniffers: List[AsyncSniffer], ports, policy_filename, policy_name, expected_rules):
    """Test AMEX egress consolidated rules policy conversion.

    Verifies that the predefined AMEX policy file is correctly converted
    and propagated from AGW to DPU.

    Generates one random packet per policy rule and verifies each packet
    is correctly forwarded through the DPU after the policy is applied.
    All rules in this policy are 'allow' rules, so all packets should be forwarded.
    """
    allure.dynamic.title(f"Test AMEX policy: {policy_name} ({expected_rules} rules)")
    policy_file = AGW_POLICIES_DIR / "amex" / policy_filename
    
    with allure.step("Generate random test packets from policy rules"):
        seed = random.randint(1, 100)
        logger.info(f"Using random seed: {seed} (reuse to reproduce)")
        packets = generate_packets_from_policy_file(str(policy_file), seed=seed)
        print_generated_packets(packets)
    
    with allure.step(f"Add AMEX policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        
        wait_for_timeout(30)
    
    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True
        )

    with allure.step("Setup TIMS VRF in SIM for VRF packet path"):
        cmd.sim_add_vrf(VRF_NAME_TO_ID["tims"])

    with allure.step(f"Send and verify {len(packets)} packets (one per rule)"):
        send_and_verify_packets(
            packets,
            sniffers,
            ports[0],
            failure_tolerance=0.05,
            process_vrf=True,
        )
    
    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)
        
        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)
