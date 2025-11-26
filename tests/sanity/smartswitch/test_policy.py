import allure
import pytest
from pathlib import Path

from helper.verification import (
    verify_policy_added_to_agw,
    verify_rule_hashes_extracted,
    verify_policy_in_sim_container,
    verify_sim_policies_match_agw,
    verify_sim_policy_structure,
    verify_policy_removed_from_agw,
    verify_policy_removed_from_sim
)

TESTDATA_DIR = Path(__file__).parent / "testdata" / "policies"
AGW_POLICIES_DIR = TESTDATA_DIR / "agw"
DPU_POLICIES_DIR = TESTDATA_DIR / "dpu"


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Complete Policy Lifecycle")
@allure.title("Add, verify, and remove policy through AGW and SIM")
def test_policy_lifecycle(cmd):
    policy_name = "permit-all-simple"
    policy_file_base = "permit_all_simple"
    agw_policy_file = AGW_POLICIES_DIR / f"{policy_file_base}.yaml"
    expected_dpu_policy = DPU_POLICIES_DIR / f"{policy_file_base}.json"
    
    with allure.step("Step 1: Add policy via agwctl"):
        result = cmd.agw_add_policy(str(agw_policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
    
    with allure.step("Step 2: Extract rule hashes from AGW"):
        rule_hashes = verify_rule_hashes_extracted(agw_policies)
    
    with allure.step("Step 3: Verify policy exists in SIM container"):
        sim_policies = cmd.sim_show_policies()
        verify_policy_in_sim_container(policy_name, sim_policies)
    
    with allure.step("Step 4: Verify SIM policies match AGW rule hashes"):
        verify_sim_policies_match_agw(sim_policies, rule_hashes, policy_name)
    
    with allure.step("Step 5: Verify policy structure in SIM matches expected"):
        verify_sim_policy_structure(sim_policies, expected_dpu_policy)
    
    with allure.step("Step 6: Remove policy via agwctl"):
        result = cmd.agw_remove_policy(str(agw_policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_removed_from_agw(result, agw_policies)
    
    with allure.step("Step 7: Verify policy removed from SIM container"):
        sim_policies = cmd.sim_show_policies()
        verify_policy_removed_from_sim(sim_policies)
