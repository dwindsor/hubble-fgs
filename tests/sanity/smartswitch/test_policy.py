#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

from typing import List

import allure
import pytest
from scapy.sendrecv import AsyncSniffer
from helper.verification import (
    verify_policy_added_to_agw,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim,
    verify_policies_match_agw_and_dpu,
    verify_policy_add_error,
    verify_no_policies_in_agw,
    verify_command_success,
)
from helper.policy_generator import (
    generate_vrf_policy_for_test,
    generate_vlan_policy_for_test,
    generate_vrf_and_vlan_policy_for_test,
    generate_policy_for_test,
)
from parameters.test_params import (
    get_multi_cidr_policy_params,
    get_dual_policy_multi_cidr_params,
    get_vrf_policy_params,
)
from helper.utils import wait_for_timeout, get_last_packet_from_sniffer
from helper.constants import AGW_POLICIES_DIR
from helper.packet_builder import build_packet
from helper.packet_utils import send_packet_and_sniff
from helper.packet_verification import verify_packet_processed


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Complete Policy Lifecycle")
@allure.title("Add, verify, and remove static policy through AGW and SIM")
def test_policy_lifecycle(cmd):
    """Test policy lifecycle with permit-all-simple policy."""
    policy_name = "permit-all-simple"
    policy_file_base = "permit_all_simple"
    agw_policy_file = AGW_POLICIES_DIR / f"{policy_file_base}.yaml"

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(agw_policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify policy matches between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(agw_policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("NXOS Policies")
@allure.title("Test L3 default VRF policy")
def test_l3_default_vrf(cmd):
    """Test L3 default VRF policy.
    Verifies policy lifecycle for default VRF with IPv4 and IPv6 rules.
    """
    policy_name = "l3-default"
    expected_rules = 2  # IPv4 + IPv6

    with allure.step("Generate policy YAML with default VRF"):
        policy, policy_file = generate_vrf_policy_for_test(
            name=policy_name, vrfs=["default"]
        )

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("NXOS Policies")
@allure.title("Test L3 EPBR VRF policies (epbr-1001 to epbr-1025)")
def test_l3_epbr_vrf(cmd):
    """Test L3 EPBR VRF policies (epbr-1001 to epbr-1025).
    Verifies policy lifecycle for 25 EPBR VRFs with IPv4 and IPv6 rules.
    """
    policy_name = "l3-epbr"
    expected_rules = 50  # 25 VRFs × 2 IP versions

    with allure.step("Generate policy YAML with EPBR range (1001-1025)"):
        policy, policy_file = generate_vrf_policy_for_test(
            name=policy_name, epbr_range=(1001, 1025)
        )

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("NXOS Policies")
@allure.title("Test L3 TRM VRF policies (trmvrf-3001 to trmvrf-3075)")
def test_l3_trmvrf(cmd):
    """Test L3 TRM VRF policies (trmvrf-3001 to trmvrf-3075).
    Verifies policy lifecycle for 75 TRM VRFs with IPv4 and IPv6 rules.
    """
    policy_name = "l3-trmvrf"
    expected_rules = 150  # 75 VRFs × 2 IP versions

    with allure.step("Generate policy YAML with TRM VRF range (3001-3075)"):
        policy, policy_file = generate_vrf_policy_for_test(
            name=policy_name, trmvrf_range=(3001, 3075)
        )

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
# @pytest.mark.skip(reason="Pending IPv6 parsing fix")
@allure.feature("Policy Management")
@allure.story("NXOS Policies")
@allure.title("Test L2 VLAN policies with specific IPs (VLAN 801-900)")
def test_l2_vlan_with_ip(cmd):
    """Test L2 VLAN policies with specific IP addresses (VLAN 801-900).

    VLANs 801-900 have specific subnet CIDRs:
    - IPv4: 191.168.X.0/24 where X = VLAN - 800
    - IPv6: 1910:168:1:X::/64 where X = hex(VLAN - 800)

    Verifies policy lifecycle for 100 VLANs with IPv4 and IPv6 rules.
    """
    policy_name = "l2-vlan-ip"
    expected_rules = 200  # 100 VLANs × 2 IP versions

    with allure.step(
        "Generate policy YAML with VLAN range (801-900) with specific IPs"
    ):
        policy, policy_file = generate_vlan_policy_for_test(
            name=policy_name, vlan_with_ip_range=(801, 900)
        )

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("NXOS Policies")
@pytest.mark.parametrize(
    "vlan_start,vlan_end",
    [
        (1001, 1100),
        (1101, 1200),
        (1201, 1300),
        (1301, 1400),
        (1401, 1500),
        (1501, 1600),
        (1601, 1700),
        (1701, 1800),
        (1801, 1900),
    ],
)
def test_l2_vlan_any_ip(cmd, vlan_start, vlan_end):
    """Test L2 VLAN policies without specific IP addresses.

    VLANs 1001-1900 use wildcard CIDRs:
    - IPv4: 0.0.0.0/0
    - IPv6: ::/0

    Parametrized to test 100 VLANs per run (200 rules each).
    """
    policy_name = f"l2-vlan-any-{vlan_start}-{vlan_end}"
    expected_rules = 200  # 100 VLANs × 2 IP versions

    with allure.step(
        f"Generate policy YAML with VLAN range ({vlan_start}-{vlan_end}) without specific IPs"
    ):
        policy, policy_file = generate_vlan_policy_for_test(
            name=policy_name, vlan_any_ip_range=(vlan_start, vlan_end)
        )

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Complex Policies")
@allure.title("Test policy with multiple CIDRs and port ranges")
def test_several_cidr_policy(cmd):
    """Test policy with multiple source/destination CIDRs and port ranges.

    This policy contains:
    - 3 source CIDRs (some with VRF)
    - 3 destination CIDRs
    - 11 protoPorts (TCP and UDP with port ranges)

    Expected rule expansion: 3 × 3 = 9 rules (CIDRs expanded, protoPorts per rule)
    """
    policy_name, rules, expected_rules = get_multi_cidr_policy_params()

    with allure.step("Generate policy YAML with multiple CIDRs and port ranges"):
        policy, policy_file = generate_policy_for_test(name=policy_name, rules=rules)

    with allure.step(f"Add policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Verify {expected_rules} rules match between AGW and DPU"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=expected_rules,
            strict_protocol_check=True,
        )

    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Validation")
@allure.title("Reject policy with both VRF and VLAN set on same ipBlock")
def test_reject_policy_with_vrf_and_vlan(cmd):
    """Test that AGW rejects a policy with both VRF and VLAN set on the same ipBlock."""

    policy_name = "invalid-vrf-vlan"

    with allure.step("Generate policy YAML with both VRF and VLAN set"):
        _, policy_file = generate_vrf_and_vlan_policy_for_test(
            name=policy_name, vrf="epbr-1001", vlan=100
        )

    with allure.step(f"Attempt to add invalid policy '{policy_name}' via agwctl"):
        result = cmd.agw_add_policy(str(policy_file))

    with allure.step("Verify AGW rejected the policy with appropriate error"):
        verify_policy_add_error(
            result, "at most one of the fields in [vrf vlan] may be set"
        )

    with allure.step("Verify no policies were added to AGW"):
        agw_policies = cmd.agw_show_policies()
        verify_no_policies_in_agw(agw_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Complex Policies")
@allure.title("Test dual policies with multi-CIDR rules and mixed port configurations")
def test_dual_policy_multi_cidr(cmd):
    """Test dual policies with multi-CIDR rules and mixed port configurations."""
    (
        policy1_name,
        policy1_rules,
        policy1_expected_rules,
        policy2_name,
        policy2_rules,
        policy2_expected_rules,
    ) = get_dual_policy_multi_cidr_params()

    total_expected_rules = policy1_expected_rules + policy2_expected_rules

    with allure.step(f"Add TCP policy '{policy1_name}' via agwctl"):
        policy1, policy1_file = generate_policy_for_test(
            name=policy1_name, rules=policy1_rules
        )
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies)
        wait_for_timeout(2)

    with allure.step(f"Add UDP policy '{policy2_name}' via agwctl"):
        policy2, policy2_file = generate_policy_for_test(
            name=policy2_name, rules=policy2_rules
        )
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(
            result, policy2_name, agw_policies, expected_policy_count=2
        )
        wait_for_timeout(2)

    with allure.step(
        f"Verify {total_expected_rules} total rules match between AGW and DPU"
    ):
        sim_policies = cmd.sim_show_policies()

        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=policy1_expected_rules,
            strict_protocol_check=True,
        )

        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=policy2_expected_rules,
            strict_protocol_check=True,
        )

    with allure.step(f"Remove TCP policy '{policy1_name}'"):
        result = cmd.agw_remove_policy(str(policy1_file))
        assert verify_command_success(result, "AGW remove policy"), (
            f"AGW remove policy command failed for {policy1_name}"
        )
        wait_for_timeout(2)

    with allure.step(f"Remove UDP policy '{policy2_name}' and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)

        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)


@pytest.mark.agw
@pytest.mark.packet_flow
@allure.feature("Packet Flow")
@allure.story("Packet flow with VRF policy enforcement")
@pytest.mark.parametrize("name, rules, pkt, vrf_id", get_vrf_policy_params())
def test_packet_flow_with_vrf(cmd, ports, sniffers: List[AsyncSniffer], name, rules, pkt, vrf_id):
    policy_name = f"{name}"

    with allure.step("Generate and apply policy"):
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
            expected_rule_count=1,
        )

    with allure.step(f"Send TCP packet"):
        cmd.sim_add_vrf(vrf_id)

        send_packet_and_sniff(pkt, sniffers, ports[0], f"TCP packet")
        pkt_second_pass = build_packet()._update_dst_vrf(
            pkt,
            get_last_packet_from_sniffer(sniffers),
            2,
        )
        send_packet_and_sniff(pkt_second_pass, sniffers, ports[0])

    with allure.step(f"Verify packet to port"):
        assert verify_packet_processed(sniffers, pkt, is_transmitted=True), (
            f"Packet should be {'forwarded' if True else 'dropped'}"
        )

    with allure.step("Cleanup policy"):
        cmd.agw_remove_policy(str(policy_file))
