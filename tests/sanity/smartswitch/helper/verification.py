#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

import json
import logging
from typing import Optional

from .policy_models import (
    parse_agw_policies,
    parse_dpu_policies,
    compare_policy_rules
)

logger = logging.getLogger(__name__)


def verify_policy_in_agw(policy_name: str, agw_output: str) -> bool:
    if policy_name not in agw_output:
        logger.debug(f"AGW output: {agw_output}")
        raise AssertionError(f"Policy '{policy_name}' NOT found in AGW output")
    
    logger.info(f"Policy '{policy_name}' found in AGW output")
    return True


def verify_command_success(output: str, command_name: str = "command") -> bool:
    assert len(output) > 0, f"{command_name} returned empty output"
    logger.info(f"{command_name} executed successfully (output length: {len(output)})")
    return True


def verify_no_policies_in_sim(sim_output: str) -> bool:
    """Verify no policies exist in SIM container"""
    assert sim_output, "SIM output is empty"
    
    data = json.loads(sim_output)
    policies = data.get("p_policy", {}).get("policies", [])
    
    if policies:
        logger.debug(f"SIM policies: {[p.get('name') for p in policies]}")
        raise AssertionError(f"Expected no policies but found {len(policies)} policies in SIM")
    
    logger.info("No policies in SIM (as expected)")
    return True


def verify_no_policies_in_agw(agw_output: str) -> bool:
    """Verify no policies exist in AGW"""
    assert agw_output, "AGW output is empty"
    
    no_policies = "No policies loaded" in agw_output or "Total Policies: 0" in agw_output
    
    if not no_policies:
        logger.debug(f"AGW output: {agw_output}")
        raise AssertionError("Expected no policies but AGW shows policies exist")
    
    logger.info("No policies in AGW (as expected)")
    return True


def verify_policy_added_to_agw(result: str, policy_name: str, agw_output: str) -> None:
    assert verify_command_success(result, "AGW add policy"), \
        f"AGW add policy command failed"
    assert "Policies added successfully" in result, \
        f"Expected success message but got: {result}"
    assert verify_policy_in_agw(policy_name, agw_output), \
        f"Policy '{policy_name}' not found in AGW policies output"
    assert "Total Policies: 1" in agw_output, \
        f"Expected 1 policy but got different count"
    logger.info(f"✅ Policy '{policy_name}' successfully added to AGW")


def verify_policy_removed_from_agw(result: str, agw_output: str) -> None:
    assert verify_command_success(result, "AGW remove policy"), \
        f"AGW remove policy command failed"
    assert "Policies removed successfully" in result, \
        f"Expected success message but got: {result}"
    assert verify_no_policies_in_agw(agw_output), \
        f"Expected no policies in AGW but found some"
    logger.info(f"✅ Policy successfully removed from AGW")


def verify_policy_removed_from_sim(sim_output: str) -> None:
    assert verify_no_policies_in_sim(sim_output), \
        f"Expected no policies in SIM but found some"
    logger.info(f"✅ Policy successfully removed from SIM")


def verify_policies_match_agw_and_dpu(
    agw_output: str,
    dpu_output: str,
    policy_name: str,
    expected_rule_count: Optional[int] = None,
    strict_protocol_check: bool = False
) -> bool:
    """
    Unified verification that policies match between AGW and DPU.
    
    This is the main entry point for policy verification. It:
    1. Parses AGW output to extract rules
    2. Parses DPU output to extract rules
    3. Compares rule counts, hashes, and details
    4. Provides detailed error messages on mismatch
    
    Args:
        agw_output: Output from 'agwctl policies show'
        dpu_output: Output from 'dpctl hs policies show' (JSON format)
        policy_name: Name of the policy to verify
        expected_rule_count: Optional expected number of rules
        strict_protocol_check: If True, verify protocols match exactly
    
    Returns:
        True if policies match, raises AssertionError otherwise
    """
    logger.info(f"Verifying policy '{policy_name}' between AGW and DPU...")
    
    # Parse both outputs
    agw_rules = parse_agw_policies(agw_output)
    dpu_rules = parse_dpu_policies(dpu_output)
    
    # Verify expected rule count if provided
    if expected_rule_count is not None:
        if len(agw_rules) != expected_rule_count:
            raise AssertionError(
                f"AGW rule count mismatch: expected {expected_rule_count}, "
                f"got {len(agw_rules)}"
            )
        if len(dpu_rules) != expected_rule_count:
            raise AssertionError(
                f"DPU rule count mismatch: expected {expected_rule_count}, "
                f"got {len(dpu_rules)}"
            )
        logger.info(f"✅ Rule count matches expected: {expected_rule_count}")
    
    # Compare rules
    comparison = compare_policy_rules(
        agw_rules, dpu_rules, policy_name
    )
    
    # Get summary message
    message = comparison.get_summary()
    
    if not comparison.success:
        logger.error(message)
        raise AssertionError(message)
    
    logger.info(message)
    return True
