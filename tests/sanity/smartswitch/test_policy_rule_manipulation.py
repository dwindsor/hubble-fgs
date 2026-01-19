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
    verify_policies_match_agw_and_dpu,
    verify_policy_not_in_agw,
    verify_policy_removed_from_sim,
)
from helper.policy_generator import generate_policy_for_test
from helper.utils import wait_for_timeout
from parameters.test_params import (
    get_initial_incremental_policy,
    get_incremental_policy_3rules,
    get_incremental_policy_5rules,
    get_two_policies_single_rule,
    get_policy_5rules_initial,
    get_policy_5rules_updated_rule2,
    get_policy_5rules_updated_rule4_rule5,
    get_two_policies_for_update,
    get_policy_5rules_for_removal,
    get_policy_5rules_without_rule3,
    get_policy_5rules_without_rule2_3_4,
    get_two_policies_for_removal,
    get_three_policies_for_clear,
)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Add Policy with 2 rules, then incrementally add more rules")
def test_policy_add_then_update_with_new_rule(cmd):
    """Test policy update scenario where rules are added incrementally.
    
    This test verifies:
    1. Create Policy1 with Rule1 and Rule2
    2. Update Policy1 to add Rule3 (total 3 rules)
    3. Update Policy1 to add Rule4 and Rule5 (total 5 rules)
    4. Verify AGW and DPU output at each step
    """
    policy_name = "policy1-rule-update"
    
    with allure.step("Step 1: Create Policy with Rule1 and Rule2"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_initial_incremental_policy())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 1: AGW and DPU have 2 rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=2,
            strict_protocol_check=True
        )
    
    with allure.step("Step 2: Update Policy to add Rule3"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_incremental_policy_3rules())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: AGW and DPU have 3 rules"):        
        sim_policies = cmd.sim_show_policies()        
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=3,
            strict_protocol_check=True
        )
    
    with allure.step("Step 3: Update Policy to add Rule4 and Rule5"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_incremental_policy_5rules())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 3: AGW and DPU have 5 rules"):
        sim_policies = cmd.sim_show_policies()
        
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=5,
            strict_protocol_check=True
        )


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Add two different policies with 1 rule each")
def test_add_two_policies_single_rule(cmd):
    """Test adding two different policies sequentially.
    
    This test verifies:
    1. Add Policy1 with 1 rule
    2. Add Policy2 with 1 rule
    3. Verify both policies exist in AGW and DPU
    """
    policy1_name, policy1_rules, policy2_name, policy2_rules = get_two_policies_single_rule()
    
    with allure.step("Step 1: Add Policy1 with 1 rule"):
        _, policy1_file = generate_policy_for_test(name=policy1_name, rules=policy1_rules)
        
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 1: AGW and DPU have Policy1 with 1 rule"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
    
    with allure.step("Step 2: Add Policy2 with 1 rule"):
        _, policy2_file = generate_policy_for_test(name=policy2_name, rules=policy2_rules)
        
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy2_name, agw_policies, expected_policy_count=2)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: AGW and DPU have both policies"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Update individual rules in a 5-rule policy")
def test_update_rules_in_5rule_policy(cmd):
    """Test updating individual rules in a policy with 5 rules.
    
    This test verifies:
    1. Add policy with 5 rules
    2. Update rule2 (port 443 -> 8443) and verify
    3. Update rule4 and rule5 and verify
    """
    policy_name = "policy-5rules-update"
    
    with allure.step("Step 1: Add policy with 5 rules"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_initial())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 1: AGW and DPU have 5 rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=5,
            strict_protocol_check=True
        )
    
    with allure.step("Step 2: Update rule2 (port 443 -> 8443)"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_updated_rule2())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: AGW and DPU have updated rule2"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=5,
            strict_protocol_check=True
        )
    
    with allure.step("Step 3: Update rule4 and rule5"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_updated_rule4_rule5())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 3: AGW and DPU have updated rule4 and rule5"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=5,
            strict_protocol_check=True
        )


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Update rules in two separate policies")
def test_update_rules_in_two_policies(cmd):
    """Test updating rules in two separate policies.
    
    This test verifies:
    1. Add two policies with 1 rule each
    2. Update rule in policy1 and verify
    3. Update rule in policy2 and verify both policies
    """
    (policy1_name, policy1_initial, policy1_updated,
     policy2_name, policy2_initial, policy2_updated) = get_two_policies_for_update()
    
    with allure.step("Step 1: Add Policy1 with initial rule"):
        _, policy1_file = generate_policy_for_test(name=policy1_name, rules=policy1_initial)
        
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Step 2: Add Policy2 with initial rule"):
        _, policy2_file = generate_policy_for_test(name=policy2_name, rules=policy2_initial)
        
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy2_name, agw_policies, expected_policy_count=2)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: Both policies have initial rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
    
    with allure.step("Step 3: Update Policy1 rule (port 80 -> 8080)"):
        _, policy1_file = generate_policy_for_test(name=policy1_name, rules=policy1_updated)
        
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies, expected_policy_count=2)
        wait_for_timeout(2)
    
    with allure.step("Step 4: Update Policy2 rule (port 53 -> 5353)"):
        _, policy2_file = generate_policy_for_test(name=policy2_name, rules=policy2_updated)
        
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy2_name, agw_policies, expected_policy_count=2)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 4: Both policies have updated rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Remove rules from a 5-rule policy")
def test_remove_rules_from_policy(cmd):
    """Test removing rules from a policy.
    
    This test verifies:
    1. Add policy with 5 rules
    2. Remove rule3 and verify AGW and DPU have 4 rules
    3. Remove rule2 and rule4 and verify AGW and DPU have 2 rules
    """
    policy_name = "policy-5rules-removal"
    
    with allure.step("Step 1: Add policy with 5 rules"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_for_removal())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 1: AGW and DPU have 5 rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=5,
            strict_protocol_check=True
        )
    
    with allure.step("Step 2: Remove rule3 from policy"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_without_rule3())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: AGW and DPU have 4 rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=4,
            strict_protocol_check=True
        )
    
    with allure.step("Step 3: Remove rule2 and rule4 from policy"):
        _, policy_file = generate_policy_for_test(name=policy_name, rules=get_policy_5rules_without_rule2_3_4())
        
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 3: AGW and DPU have 2 rules"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy_name,
            expected_rule_count=2,
            strict_protocol_check=True
        )


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Remove one policy while keeping another")
def test_remove_policy_keep_other(cmd):
    """Test removing one policy while another remains.
    
    This test verifies:
    1. Add two policies with 1 rule each
    2. Remove policy2
    3. Verify policy1 is still present in AGW and DPU
    """
    policy1_name, policy1_rules, policy2_name, policy2_rules = get_two_policies_for_removal()
    
    with allure.step("Step 1: Add Policy1 with 1 rule"):
        _, policy1_file = generate_policy_for_test(name=policy1_name, rules=policy1_rules)
        
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies)
        wait_for_timeout(2)
    
    with allure.step("Step 2: Add Policy2 with 1 rule"):
        _, policy2_file = generate_policy_for_test(name=policy2_name, rules=policy2_rules)
        
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy2_name, agw_policies, expected_policy_count=2)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 2: Both policies exist"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
    
    with allure.step("Step 3: Remove Policy2"):
        result = cmd.agw_remove_policy(str(policy2_file))
        wait_for_timeout(2)
    
    with allure.step("Verify Step 3: Policy1 still exists, Policy2 removed"):
        agw_policies = cmd.agw_show_policies()
        sim_policies = cmd.sim_show_policies()
        
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        
        verify_policy_not_in_agw(policy2_name, agw_policies)


@pytest.mark.agw
@pytest.mark.policy
@allure.feature("Policy Management")
@allure.story("Policy Rule Manipulation")
@allure.title("Clear all policies")
def test_clear_all_policies(cmd):
    """Test clearing all policies.
    
    This test verifies:
    1. Add three policies with 1 rule each
    2. Clear all policies
    3. Verify no policies exist in AGW and DPU
    """
    (policy1_name, policy1_rules,
     policy2_name, policy2_rules,
     policy3_name, policy3_rules) = get_three_policies_for_clear()
    
    with allure.step("Step 1: Add Policy1"):
        _, policy1_file = generate_policy_for_test(name=policy1_name, rules=policy1_rules)
        result = cmd.agw_add_policy(str(policy1_file))
        verify_policy_added_to_agw(result, policy1_name, cmd.agw_show_policies())
        wait_for_timeout(1)
    
    with allure.step("Step 2: Add Policy2"):
        _, policy2_file = generate_policy_for_test(name=policy2_name, rules=policy2_rules)
        result = cmd.agw_add_policy(str(policy2_file))
        verify_policy_added_to_agw(result, policy2_name, cmd.agw_show_policies(), expected_policy_count=2)
        wait_for_timeout(1)
    
    with allure.step("Step 3: Add Policy3"):
        _, policy3_file = generate_policy_for_test(name=policy3_name, rules=policy3_rules)
        result = cmd.agw_add_policy(str(policy3_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy3_name, agw_policies, expected_policy_count=3)
        wait_for_timeout(2)
    
    with allure.step("Verify Step 3: All three policies exist"):
        sim_policies = cmd.sim_show_policies()
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy1_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy2_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
        verify_policies_match_agw_and_dpu(
            agw_output=agw_policies,
            dpu_output=sim_policies,
            policy_name=policy3_name,
            expected_rule_count=1,
            strict_protocol_check=True
        )
    
    with allure.step("Step 4: Clear all policies"):
        cmd.agw_clear_policies()
        wait_for_timeout(2)
    
    with allure.step("Verify Step 4: No policies exist in AGW and SIM"):
        agw_policies = cmd.agw_show_policies()
        sim_policies = cmd.sim_show_policies()
        
        verify_policy_not_in_agw(policy1_name, agw_policies)
        verify_policy_not_in_agw(policy2_name, agw_policies)
        verify_policy_not_in_agw(policy3_name, agw_policies)
        
        verify_policy_removed_from_sim(sim_policies)