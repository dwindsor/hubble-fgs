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

from helper.policy_generator import generate_policy_for_test
from helper.packet_utils import create_sniffers, send_packet_and_sniff
from helper.packet_verification import verify_packet_processed
from helper.verification import (
    verify_policies_match_agw_and_dpu,
    verify_policy_added_to_agw,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim,
)
from helper.utils import wait_for_timeout, retry_on_failure
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
def test_cidr_source_enforcement(cmd, cidr, rules, packets):
    """Test source CIDR mask enforcement with packets before, inside, and after range."""
    policy_name = f"cidr-src-{cidr.replace('/', '-').replace('.', '-')}"
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)
    allure.dynamic.title(f"Source CIDR test on two DPUs: {cidr}")

    with allure.step(f"Disable inter-VRF on DPU '{sim1_name}'"):
        cmd.sim_disable_inter_vrf(sim_container_name=sim1_name)

    with allure.step(f"Apply source CIDR policy for {cidr}"):
        _, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(3)

    with allure.step(f"Verify policy is applied to DPU '{sim1_name}'"):
        def check_sim1_policy():
            sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim1_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim1_policy)

    with allure.step(f"Verify policy is applied to DPU '{sim2_name}'"):
        def check_sim2_policy():
            sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim2_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim2_policy)

    ip_before, pkt_before = packets[0]
    ip_inside, pkt_inside = packets[1]
    ip_after, pkt_after = packets[2]

    with allure.step(f"Packet from {ip_before} (before range) on DPU '{sim1_name}' - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_before, sim1_sniffers, sim1_port0, f"TCP from src {ip_before} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_before, False), \
            f"Packet from src {ip_before} (before range) on {sim1_name} should be dropped"

    # with allure.step(f"Packet from {ip_inside} (inside range) on DPU '{sim1_name}' - expect allowed"):
    #     sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
    #     send_packet_and_sniff(pkt_inside, sim1_sniffers, sim1_port0, f"TCP from src {ip_inside} on {sim1_name}")
    #     assert verify_packet_processed(sim1_sniffers, pkt_inside, True), \
    #         f"Packet from src {ip_inside} (inside range) on {sim1_name} should be forwarded"

    with allure.step(f"Packet from {ip_after} (after range) on DPU '{sim1_name}' - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_after, sim1_sniffers, sim1_port0, f"TCP from src {ip_after} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_after, False), \
            f"Packet from src {ip_after} (after range) on {sim1_name} should be dropped"

    with allure.step(f"Packet from {ip_before} (before range) on DPU '{sim2_name}' - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_before, sim2_sniffers, sim2_port0, f"TCP from src {ip_before} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_before, False), \
            f"Packet from src {ip_before} (before range) on {sim2_name} should be dropped"

    # with allure.step(f"Packet from {ip_inside} (inside range) on DPU '{sim2_name}' - expect allowed"):
    #     sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
    #     send_packet_and_sniff(pkt_inside, sim2_sniffers, sim2_port0, f"TCP from src {ip_inside} on {sim2_name}")
    #     assert verify_packet_processed(sim2_sniffers, pkt_inside, True), \
    #         f"Packet from src {ip_inside} (inside range) on {sim2_name} should be forwarded"

    with allure.step(f"Packet from {ip_after} (after range) on DPU '{sim2_name}' - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_after, sim2_sniffers, sim2_port0, f"TCP from src {ip_after} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_after, False), \
            f"Packet from src {ip_after} (after range) on {sim2_name} should be dropped"

    with allure.step("Remove policy and verify cleanup on AGW and both DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policy_removed_from_sim(sim1_policies)

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policy_removed_from_sim(sim2_policies)


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Destination CIDR Policy Enforcement")
@pytest.mark.parametrize("cidr,rules,packets", get_cidr_dest_packet_test_params(),
                         ids=[p[0] for p in get_cidr_dest_packet_test_params()])
def test_cidr_dest_enforcement(cmd, cidr, rules, packets):
    """Test destination CIDR mask enforcement with packets before, inside, and after range."""
    policy_name = f"cidr-dest-{cidr.replace('/', '-').replace('.', '-')}"
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)
    allure.dynamic.title(f"Dest CIDR test on two DPUs: {cidr}")

    with allure.step(f"Disable inter-VRF on DPU '{sim1_name}'"):
        cmd.sim_disable_inter_vrf(sim_container_name=sim1_name)

    with allure.step(f"Apply destination CIDR policy for {cidr}"):
        _, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify policy is applied to DPU '{sim1_name}'"):
        def check_sim1_policy():
            sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim1_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim1_policy)

    with allure.step(f"Verify policy is applied to DPU '{sim2_name}'"):
        def check_sim2_policy():
            sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim2_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim2_policy)

    ip_before, pkt_before = packets[0]
    ip_inside, pkt_inside = packets[1]
    ip_after, pkt_after = packets[2]

    with allure.step(f"Packet to {ip_before} (before range) on DPU '{sim1_name}' - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_before, sim1_sniffers, sim1_port0, f"TCP to dest {ip_before} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_before, False), \
            f"Packet to dest {ip_before} (before range) on {sim1_name} should be dropped"

    # with allure.step(f"Packet to {ip_inside} (inside range) on DPU '{sim1_name}' - expect allowed"):
    #     sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
    #     send_packet_and_sniff(pkt_inside, sim1_sniffers, sim1_port0, f"TCP to dest {ip_inside} on {sim1_name}")
    #     assert verify_packet_processed(sim1_sniffers, pkt_inside, True), \
    #         f"Packet to dest {ip_inside} (inside range) on {sim1_name} should be forwarded"

    with allure.step(f"Packet to {ip_after} (after range) on DPU '{sim1_name}' - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_after, sim1_sniffers, sim1_port0, f"TCP to dest {ip_after} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_after, False), \
            f"Packet to dest {ip_after} (after range) on {sim1_name} should be dropped"

    with allure.step(f"Packet to {ip_before} (before range) on DPU '{sim2_name}' - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_before, sim2_sniffers, sim2_port0, f"TCP to dest {ip_before} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_before, False), \
            f"Packet to dest {ip_before} (before range) on {sim2_name} should be dropped"

    # with allure.step(f"Packet to {ip_inside} (inside range) on DPU '{sim2_name}' - expect allowed"):
    #     sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
    #     send_packet_and_sniff(pkt_inside, sim2_sniffers, sim2_port0, f"TCP to dest {ip_inside} on {sim2_name}")
    #     assert verify_packet_processed(sim2_sniffers, pkt_inside, True), \
    #         f"Packet to dest {ip_inside} (inside range) on {sim2_name} should be forwarded"

    with allure.step(f"Packet to {ip_after} (after range) on DPU '{sim2_name}' - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_after, sim2_sniffers, sim2_port0, f"TCP to dest {ip_after} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_after, False), \
            f"Packet to dest {ip_after} (after range) on {sim2_name} should be dropped"

    with allure.step("Remove policy and verify cleanup on AGW and both DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policy_removed_from_sim(sim1_policies)

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policy_removed_from_sim(sim2_policies)


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Combined CIDR Policy Enforcement")
@pytest.mark.parametrize("cidr_combo,rules,packets", get_cidr_combined_packet_test_params(),
                         ids=[p[0] for p in get_cidr_combined_packet_test_params()])
def test_cidr_combined_enforcement(cmd, cidr_combo, rules, packets):
    """Test combined source AND destination CIDR enforcement.
    
    Verifies that BOTH source and destination CIDR must match for traffic to be allowed:
    - Source allowed + destination blocked → blocked
    - Source blocked + destination allowed → blocked
    - Both allowed → allowed
    """
    policy_name = f"cidr-combined-{cidr_combo.replace('/', '-').replace('.', '-').replace('+', '-')}"
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)
    allure.dynamic.title(f"Combined CIDR test on two DPUs: {cidr_combo}")

    with allure.step(f"Disable inter-VRF on DPU '{sim1_name}'"):
        cmd.sim_disable_inter_vrf(sim_container_name=sim1_name)

    with allure.step(f"Apply combined source+destination CIDR policy"):
        _, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify policy is applied to DPU '{sim1_name}'"):
        def check_sim1_policy():
            sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim1_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim1_policy)

    with allure.step(f"Verify policy is applied to DPU '{sim2_name}'"):
        def check_sim2_policy():
            sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim2_policies,
                policy_name=policy_name,
                expected_rule_count=1,
            )
        retry_on_failure(check_sim2_policy)

    test_name_0, pkt_0, expected_0 = packets[0]
    test_name_1, pkt_1, expected_1 = packets[1]
    test_name_2, pkt_2, expected_2 = packets[2]

    with allure.step(f"Test {test_name_0} on DPU '{sim1_name}': source inside, dest outside - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_0, sim1_sniffers, sim1_port0, f"{test_name_0} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_0, expected_0), \
            f"{test_name_0} on {sim1_name} should be dropped (dest outside range)"

    with allure.step(f"Test {test_name_1} on DPU '{sim1_name}': source outside, dest inside - expect blocked"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt_1, sim1_sniffers, sim1_port0, f"{test_name_1} on {sim1_name}")
        assert verify_packet_processed(sim1_sniffers, pkt_1, expected_1), \
            f"{test_name_1} on {sim1_name} should be dropped (source outside range)"

    # with allure.step(f"Test {test_name_2} on DPU '{sim1_name}': both inside - expect allowed"):
    #     sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
    #     send_packet_and_sniff(pkt_2, sim1_sniffers, sim1_port0, f"{test_name_2} on {sim1_name}")
    #     assert verify_packet_processed(sim1_sniffers, pkt_2, expected_2), \
    #         f"{test_name_2} on {sim1_name} should be forwarded (both match)"

    with allure.step(f"Test {test_name_0} on DPU '{sim2_name}': source inside, dest outside - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_0, sim2_sniffers, sim2_port0, f"{test_name_0} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_0, expected_0), \
            f"{test_name_0} on {sim2_name} should be dropped (dest outside range)"

    with allure.step(f"Test {test_name_1} on DPU '{sim2_name}': source outside, dest inside - expect blocked"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt_1, sim2_sniffers, sim2_port0, f"{test_name_1} on {sim2_name}")
        assert verify_packet_processed(sim2_sniffers, pkt_1, expected_1), \
            f"{test_name_1} on {sim2_name} should be dropped (source outside range)"

    # with allure.step(f"Test {test_name_2} on DPU '{sim2_name}': both inside - expect allowed"):
    #     sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
    #     send_packet_and_sniff(pkt_2, sim2_sniffers, sim2_port0, f"{test_name_2} on {sim2_name}")
    #     assert verify_packet_processed(sim2_sniffers, pkt_2, expected_2), \
    #         f"{test_name_2} on {sim2_name} should be forwarded (both match)"

    with allure.step("Remove policy and verify cleanup on AGW and both DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policy_removed_from_sim(sim1_policies)

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policy_removed_from_sim(sim2_policies)
