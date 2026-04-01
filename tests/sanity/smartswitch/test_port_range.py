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

from helper.verification import (
    verify_policy_added_to_agw,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim,
    verify_policies_match_agw_and_dpu
)
from helper.policy_generator import generate_policy_for_test
from helper.packet_utils import create_sniffers, send_packet_and_sniff
from helper.packet_verification import verify_packet_processed
from helper.utils import wait_for_timeout
from parameters.test_params import get_port_proto_test_params, get_port_range_packet_test_params, get_protocol_packet_test_params


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("L3 Policies with Ports")
@pytest.mark.parametrize("policy_name,rules", get_port_proto_test_params(), ids=[p[0] for p in get_port_proto_test_params()])
def test_l3_policies_with_ports(cmd, policy_name, rules):
    """Test L3 policies with comprehensive port and protocol combinations.

    Coverage matrix:
    - Single port: 1 protocol, 2 protocols, 3 protocols (any)
    - Port range: 1 protocol, 2 protocols, 3 protocols (any)
    
    Note: When 3 protocols (TCP+UDP+ICMP) are specified, DPU shows 'any' protocol.
    """
    allure.dynamic.title(f"Test port/protocol policy: {policy_name}")
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    
    with allure.step(f"Generate policy '{policy_name}'"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(1)

    with allure.step(f"Verify {len(rules)} rules match between AGW and DPU"):
        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim1_policies,
            policy_name=policy_name,
            expected_rule_count=len(rules),
        )
        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim2_policies,
            policy_name=policy_name,
            expected_rule_count=len(rules),
        )

    with allure.step(f"Remove policy '{policy_name}' and verify cleanup"):
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
@allure.story("Port Range Policy Enforcement")
@pytest.mark.parametrize("test_port,is_transmitted,rules,pkt", get_port_range_packet_test_params(),
                         ids=[f"port-{p[0]}" for p in get_port_range_packet_test_params()])
def test_port_range_enforcement(cmd, test_port, is_transmitted, rules, pkt):
    policy_name = f"port-range-test-{test_port}"
    allure.dynamic.title(f"Port range test: port {test_port} ({'allowed' if is_transmitted else 'blocked'})")
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)

    with allure.step(f"Disable inter-VRF on DPU '{sim1_name}'"):
        cmd.sim_disable_inter_vrf(sim_container_name=sim1_name)

    with allure.step("Generate and apply policy"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify policy is applied to DPU '{sim1_name}'"):
        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim1_policies,
            policy_name=policy_name,
            expected_rule_count=1,
        )

    with allure.step(f"Verify policy is applied to DPU '{sim2_name}'"):
        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim2_policies,
            policy_name=policy_name,
            expected_rule_count=1,
        )

    with allure.step(f"Send TCP packet to port {test_port} on DPU '{sim1_name}'"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt, sim1_sniffers, sim1_port0, f"TCP to port {test_port} on {sim1_name}")

    with allure.step(f"Verify packet on DPU '{sim1_name}' was {'forwarded' if is_transmitted else 'dropped'}"):
        assert verify_packet_processed(sim1_sniffers, pkt, is_transmitted), \
            f"Packet to port {test_port} on {sim1_name} should be {'forwarded' if is_transmitted else 'dropped'}"

    with allure.step(f"Send TCP packet to port {test_port} on DPU '{sim2_name}'"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt, sim2_sniffers, sim2_port0, f"TCP to port {test_port} on {sim2_name}")

    with allure.step(f"Verify packet on DPU '{sim2_name}' was {'forwarded' if is_transmitted else 'dropped'}"):
        assert verify_packet_processed(sim2_sniffers, pkt, is_transmitted), \
            f"Packet to port {test_port} on {sim2_name} should be {'forwarded' if is_transmitted else 'dropped'}"

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
@allure.story("Protocol Policy Enforcement")
@pytest.mark.parametrize("protocol,is_transmitted,rules,pkt", get_protocol_packet_test_params(),
                         ids=[f"proto-{p[0]}" for p in get_protocol_packet_test_params()])
def test_protocol_enforcement(cmd, protocol, is_transmitted, rules, pkt):
    policy_name = f"protocol-test-{protocol.lower()}"
    allure.dynamic.title(f"Protocol test: {protocol} ({'allowed' if is_transmitted else 'blocked'})")
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)

    with allure.step(f"Disable inter-VRF on DPU '{sim1_name}'"):
        cmd.sim_disable_inter_vrf(sim_container_name=sim1_name)

    with allure.step("Generate and apply policy allowing only TCP"):
        policy, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify policy is applied to DPU '{sim1_name}'"):
        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim1_policies,
            policy_name=policy_name,
            expected_rule_count=1,
        )

    with allure.step(f"Verify policy is applied to DPU '{sim2_name}'"):
        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim2_policies,
            policy_name=policy_name,
            expected_rule_count=1,
        )

    with allure.step(f"Send {protocol} packet on DPU '{sim1_name}'"):
        sim1_sniffers = create_sniffers([sim1_port0, sim1_port1])
        send_packet_and_sniff(pkt, sim1_sniffers, sim1_port0, f"{protocol} packet on {sim1_name}")

    with allure.step(f"Verify {protocol} packet on DPU '{sim1_name}' was {'forwarded' if is_transmitted else 'dropped'}"):
        assert verify_packet_processed(sim1_sniffers, pkt, is_transmitted), \
            f"{protocol} packet on {sim1_name} should be {'forwarded' if is_transmitted else 'dropped'}"

    with allure.step(f"Send {protocol} packet on DPU '{sim2_name}'"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(pkt, sim2_sniffers, sim2_port0, f"{protocol} packet on {sim2_name}")

    with allure.step(f"Verify {protocol} packet on DPU '{sim2_name}' was {'forwarded' if is_transmitted else 'dropped'}"):
        assert verify_packet_processed(sim2_sniffers, pkt, is_transmitted), \
            f"{protocol} packet on {sim2_name} should be {'forwarded' if is_transmitted else 'dropped'}"

    with allure.step("Remove policy and verify cleanup on AGW and both DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policy_removed_from_sim(sim1_policies)
        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policy_removed_from_sim(sim2_policies)
