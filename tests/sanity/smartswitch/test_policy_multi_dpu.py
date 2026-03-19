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
from helper.utils import wait_for_timeout
from parameters.test_params import (
    get_multi_cidr_policy_params,
    get_port_range_packet_test_params,
)


@pytest.mark.skip(
    reason="Skipping until multi-sim configuration implemented in GitHub pipeline"
)
@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Complex Policies")
@allure.title("Test policy with multiple CIDRs and port ranges on two DPUs")
def test_several_cidr_policy_two_dpus(cmd):
    """Validate multi-CIDR policy propagation and cleanup on two DPU simulators."""
    sim1_name, sim2_name = cmd.get_two_sim_container_names()

    policy_name, rules, expected_rules = get_multi_cidr_policy_params()

    with allure.step("Generate policy YAML with multiple CIDRs and port ranges"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=rules)

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(
        f"Verify {expected_rules} rules match between AGW and each DPU simulator"
    ):
        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        with allure.step(f"Verify policy on SIM container '{sim1_name}'"):
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim1_policies,
                policy_name=policy_name,
                expected_rule_count=expected_rules,
                strict_protocol_check=True,
            )

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        with allure.step(f"Verify policy on SIM container '{sim2_name}'"):
            verify_policies_match_agw_and_dpu(
                agw_output=agw_policies,
                dpu_output=sim2_policies,
                policy_name=policy_name,
                expected_rule_count=expected_rules,
                strict_protocol_check=True,
            )

    with allure.step("Remove policy and verify cleanup on AGW and all DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        with allure.step(f"Verify policy removed on SIM container '{sim1_name}'"):
            verify_policy_removed_from_sim(sim1_policies)

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        with allure.step(f"Verify policy removed on SIM container '{sim2_name}'"):
            verify_policy_removed_from_sim(sim2_policies)


@pytest.mark.skip(
    reason="Skipping until multi-sim configuration implemented in GitHub pipeline"
)
@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Port Range Policy Enforcement")
@pytest.mark.parametrize(
    "test_port,is_transmitted,rules,pkt",
    get_port_range_packet_test_params(),
    ids=[f"port-{p[0]}" for p in get_port_range_packet_test_params()],
)
def test_port_range_enforcement_two_dpus(
    cmd, test_port, is_transmitted, rules, pkt
):
    policy_name = f"port-range-two-dpu-{test_port}"
    sim1_name, sim2_name = cmd.get_two_sim_container_names()
    sim1_port0, sim1_port1 = cmd.get_sim_host_uplink_ports(sim1_name)
    sim2_port0, sim2_port1 = cmd.get_sim_host_uplink_ports(sim2_name)
    expectation = {True: "forwarded", False: "dropped"}[is_transmitted]
    policy_state = {True: "allowed", False: "blocked"}[is_transmitted]

    allure.dynamic.title(
        f"Port range on two DPUs: port {test_port} ({policy_state})"
    )

    with allure.step("Generate and apply policy"):
        _, policy_file = generate_policy_for_test(policy_name, rules)
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
        send_packet_and_sniff(
            pkt, sim1_sniffers, sim1_port0, f"TCP to port {test_port} on {sim1_name}"
        )

    with allure.step(
        f"Verify packet to port {test_port} on DPU '{sim1_name}' was {expectation}"
    ):
        assert verify_packet_processed(sim1_sniffers, pkt, is_transmitted), (
            f"Packet to port {test_port} on {sim1_name} should be {expectation}"
        )

    with allure.step(f"Send TCP packet to port {test_port} on DPU '{sim2_name}'"):
        sim2_sniffers = create_sniffers([sim2_port0, sim2_port1])
        send_packet_and_sniff(
            pkt, sim2_sniffers, sim2_port0, f"TCP to port {test_port} on {sim2_name}"
        )

    with allure.step(
        f"Verify packet to port {test_port} on DPU '{sim2_name}' was {expectation}"
    ):
        assert verify_packet_processed(sim2_sniffers, pkt, is_transmitted), (
            f"Packet to port {test_port} on {sim2_name} should be {expectation}"
        )

    with allure.step("Remove policy and verify cleanup on AGW and both DPUs"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim1_policies = cmd.sim_show_policies(sim_container_name=sim1_name)
        verify_policy_removed_from_sim(sim1_policies)

        sim2_policies = cmd.sim_show_policies(sim_container_name=sim2_name)
        verify_policy_removed_from_sim(sim2_policies)
