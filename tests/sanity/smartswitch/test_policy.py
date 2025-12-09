import allure
import pytest
from pathlib import Path

from helper.verification import (
    verify_policy_added_to_agw,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim,
    verify_policies_match_agw_and_dpu
)
from helper.policy_generator import generate_epbr_vrf_policy_for_test, generate_vlan_policy_for_test
from helper.utils import wait_for_timeout

TESTDATA_DIR = Path(__file__).parent / "testdata" / "policies"
AGW_POLICIES_DIR = TESTDATA_DIR / "agw"


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
            strict_protocol_check=True
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
        policy_file = generate_epbr_vrf_policy_for_test(name=policy_name, vrfs=["default"])
    
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
            strict_protocol_check=True
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
        policy_file = generate_epbr_vrf_policy_for_test(name=policy_name, epbr_range=(1001, 1025))
    
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
            strict_protocol_check=True
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
        policy_file = generate_epbr_vrf_policy_for_test(name=policy_name, trmvrf_range=(3001, 3075))
    
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
            strict_protocol_check=True
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
    
    with allure.step("Generate policy YAML with VLAN range (801-900) with specific IPs"):
        policy_file = generate_vlan_policy_for_test(name=policy_name, vlan_with_ip_range=(801, 900))
    
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
            strict_protocol_check=True
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
@pytest.mark.parametrize("vlan_start,vlan_end", [
    (1001, 1100),
    (1101, 1200),
    (1201, 1300),
    (1301, 1400),
    (1401, 1500),
    (1501, 1600),
    (1601, 1700),
    (1701, 1800),
    (1801, 1900),
])
def test_l2_vlan_any_ip(cmd, vlan_start, vlan_end):
    """Test L2 VLAN policies without specific IP addresses.
    
    VLANs 1001-1900 use wildcard CIDRs:
    - IPv4: 0.0.0.0/0
    - IPv6: ::/0
    
    Parametrized to test 100 VLANs per run (200 rules each).
    """
    policy_name = f"l2-vlan-any-{vlan_start}-{vlan_end}"
    expected_rules = 200  # 100 VLANs × 2 IP versions
    
    with allure.step(f"Generate policy YAML with VLAN range ({vlan_start}-{vlan_end}) without specific IPs"):
        policy_file = generate_vlan_policy_for_test(name=policy_name, vlan_any_ip_range=(vlan_start, vlan_end))
    
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
            strict_protocol_check=True
        )
    
    with allure.step("Remove policy and verify cleanup"):
        result = cmd.agw_remove_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)
        
        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)
