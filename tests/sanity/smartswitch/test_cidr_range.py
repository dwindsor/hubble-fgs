#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import allure
import pytest
from typing import List

from scapy.sendrecv import AsyncSniffer

from helper.verification import (
    verify_policy_added_to_agw,
    verify_policies_match_agw_and_dpu,
)
from helper.policy_generator import generate_policy_for_test
from helper.packet_utils import send_packet_and_sniff
from helper.packet_verification import verify_packet_processed
from helper.utils import wait_for_timeout
from parameters.test_params import (
    get_cidr_source_packet_test_params,
    get_cidr_dest_packet_test_params,
    get_cidr_combined_packet_test_params,
)


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Source CIDR Policy Enforcement")
@pytest.mark.parametrize("cidr,rules,packets", get_cidr_source_packet_test_params(),
                         ids=[p[0] for p in get_cidr_source_packet_test_params()])
def test_cidr_source_enforcement(cmd, sniffers: List[AsyncSniffer], ports, cidr, rules, packets):
    """Test source CIDR mask enforcement with packets before, inside, and after range."""
    policy_name = f"cidr-src-{cidr.replace('/', '-').replace('.', '-')}"
    allure.dynamic.title(f"Source CIDR test: {cidr}")

    with allure.step(f"Apply source CIDR policy for {cidr}"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify policy is applied to DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=1
        )

    ip_before, pkt_before = packets[0]
    ip_inside, pkt_inside = packets[1]
    ip_after, pkt_after = packets[2]

    with allure.step(f"Packet from {ip_before} (before range) - expect blocked"):
        send_packet_and_sniff(pkt_before, sniffers, ports[0], f"TCP from src {ip_before}")
        assert verify_packet_processed(sniffers, pkt_before, False), \
            f"Packet from src {ip_before} (before range) should be dropped"

    with allure.step(f"Packet from {ip_inside} (inside range) - expect allowed"):
        send_packet_and_sniff(pkt_inside, sniffers, ports[0], f"TCP from src {ip_inside}")
        assert verify_packet_processed(sniffers, pkt_inside, True), \
            f"Packet from src {ip_inside} (inside range) should be forwarded"

    with allure.step(f"Packet from {ip_after} (after range) - expect blocked"):
        send_packet_and_sniff(pkt_after, sniffers, ports[0], f"TCP from src {ip_after}")
        assert verify_packet_processed(sniffers, pkt_after, False), \
            f"Packet from src {ip_after} (after range) should be dropped"

    with allure.step("Cleanup policy"):
        cmd.agw_remove_policy(str(policy_file))


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Destination CIDR Policy Enforcement")
@pytest.mark.parametrize("cidr,rules,packets", get_cidr_dest_packet_test_params(),
                         ids=[p[0] for p in get_cidr_dest_packet_test_params()])
def test_cidr_dest_enforcement(cmd, sniffers: List[AsyncSniffer], ports, cidr, rules, packets):
    """Test destination CIDR mask enforcement with packets before, inside, and after range."""
    policy_name = f"cidr-dest-{cidr.replace('/', '-').replace('.', '-')}"
    allure.dynamic.title(f"Dest CIDR test: {cidr}")

    with allure.step(f"Apply destination CIDR policy for {cidr}"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify policy is applied to DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=1
        )

    ip_before, pkt_before = packets[0]
    ip_inside, pkt_inside = packets[1]
    ip_after, pkt_after = packets[2]

    with allure.step(f"Packet to {ip_before} (before range) - expect blocked"):
        send_packet_and_sniff(pkt_before, sniffers, ports[0], f"TCP to dest {ip_before}")
        assert verify_packet_processed(sniffers, pkt_before, False), \
            f"Packet to dest {ip_before} (before range) should be dropped"

    with allure.step(f"Packet to {ip_inside} (inside range) - expect allowed"):
        send_packet_and_sniff(pkt_inside, sniffers, ports[0], f"TCP to dest {ip_inside}")
        assert verify_packet_processed(sniffers, pkt_inside, True), \
            f"Packet to dest {ip_inside} (inside range) should be forwarded"

    with allure.step(f"Packet to {ip_after} (after range) - expect blocked"):
        send_packet_and_sniff(pkt_after, sniffers, ports[0], f"TCP to dest {ip_after}")
        assert verify_packet_processed(sniffers, pkt_after, False), \
            f"Packet to dest {ip_after} (after range) should be dropped"

    with allure.step("Cleanup policy"):
        cmd.agw_remove_policy(str(policy_file))


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Combined CIDR Policy Enforcement")
@pytest.mark.parametrize("cidr_combo,rules,packets", get_cidr_combined_packet_test_params(),
                         ids=[p[0] for p in get_cidr_combined_packet_test_params()])
def test_cidr_combined_enforcement(cmd, sniffers: List[AsyncSniffer], ports, cidr_combo, rules, packets):
    """Test combined source AND destination CIDR enforcement.
    
    Verifies that BOTH source and destination CIDR must match for traffic to be allowed:
    - Source allowed + destination blocked → blocked
    - Source blocked + destination allowed → blocked
    - Both allowed → allowed
    """
    policy_name = f"cidr-combined-{cidr_combo.replace('/', '-').replace('.', '-').replace('+', '-')}"
    allure.dynamic.title(f"Combined CIDR test: {cidr_combo}")

    with allure.step(f"Apply combined source+destination CIDR policy"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify policy is applied to DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=1
        )

    test_name_0, pkt_0, expected_0 = packets[0]
    test_name_1, pkt_1, expected_1 = packets[1]
    test_name_2, pkt_2, expected_2 = packets[2]

    with allure.step(f"Test {test_name_0}: source inside, dest outside - expect blocked"):
        send_packet_and_sniff(pkt_0, sniffers, ports[0], test_name_0)
        assert verify_packet_processed(sniffers, pkt_0, expected_0), \
            f"{test_name_0} should be dropped (dest outside range)"

    with allure.step(f"Test {test_name_1}: source outside, dest inside - expect blocked"):
        send_packet_and_sniff(pkt_1, sniffers, ports[0], test_name_1)
        assert verify_packet_processed(sniffers, pkt_1, expected_1), \
            f"{test_name_1} should be dropped (source outside range)"

    with allure.step(f"Test {test_name_2}: both inside - expect allowed"):
        send_packet_and_sniff(pkt_2, sniffers, ports[0], test_name_2)
        assert verify_packet_processed(sniffers, pkt_2, expected_2), \
            f"{test_name_2} should be forwarded (both match)"

    with allure.step("Cleanup policy"):
        cmd.agw_remove_policy(str(policy_file))
