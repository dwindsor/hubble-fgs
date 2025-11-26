import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Set

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


def verify_policy_in_sim(policy_name: str, sim_output: str, exact_match: bool = False) -> bool:
    assert sim_output, "SIM output is empty"
    
    data = json.loads(sim_output)
    policies = data.get("p_policy", {}).get("policies", [])
    assert policies, "No policies found in SIM output"
    
    # Check if any policy name contains our policy name
    if exact_match:
        found = any(policy_name in policy.get("name", "") for policy in policies)
    else:
        # Case-insensitive match
        policy_name_lower = policy_name.lower()
        found = any(policy_name_lower in policy.get("name", "").lower() for policy in policies)
    
    policy_names = [p.get('name') for p in policies]
    match_type = "exact" if exact_match else "case-insensitive"
    assert found, f"Policy '{policy_name}' NOT found in SIM output ({match_type} match). Available policies: {policy_names}"
    
    logger.info(f"Policy '{policy_name}' found in SIM output ({len(policies)} total policies, {match_type} match)")
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


def _normalize_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a policy by removing dynamic fields (id, name, hit_count)"""
    normalized = policy.copy()
    # Remove dynamic fields that change between runs
    normalized.pop('id', None)
    normalized.pop('name', None)
    normalized.pop('hit_count', None)
    return normalized


def _compare_policies(actual: List[Dict], expected: List[Dict]) -> None:
    """Compare two lists of policies, ignoring dynamic fields
    
    Note: Policies are sorted before comparison because the order returned by the
    dataplane may not be deterministic. Sorting ensures consistent comparison regardless
    of the order policies are returned in.
    """
    assert len(actual) == len(expected), \
        f"Policy count mismatch: expected {len(expected)}, got {len(actual)}"
    
    # Normalize both lists
    actual_normalized = [_normalize_policy(p) for p in actual]
    expected_normalized = [_normalize_policy(p) for p in expected]
    
    # Sort by a stable key to ensure deterministic comparison
    # (policies may be returned in different orders)
    def sort_key(p):
        return (
            p.get('source', {}).get('ip', ''),
            p.get('destination', {}).get('ip', ''),
            p.get('effect', '')
        )
    
    actual_normalized.sort(key=sort_key)
    expected_normalized.sort(key=sort_key)
    
    # Compare each policy
    for i, (actual_pol, expected_pol) in enumerate(zip(actual_normalized, expected_normalized)):
        assert actual_pol == expected_pol, \
            f"Policy {i} mismatch:\nExpected: {expected_pol}\nActual: {actual_pol}"


def extract_rule_hashes_from_agw(agw_output: str) -> Set[str]:
    """
    Extract rule hashes/names from AGW output.
    
    Example AGW output:
      Rule Name:   452267d4a2f80cae7597a09ed5187a8a951dbad68c335ca171e125036c2a5bab
      
    Returns:
        Set of rule hash strings
    """
    rule_hashes = set()
    
    # Pattern to match rule names (64-character hex strings)
    pattern = r'Rule Name:\s+([a-f0-9]{64})'
    matches = re.findall(pattern, agw_output)
    
    rule_hashes.update(matches)
    
    if rule_hashes:
        logger.info(f"Extracted {len(rule_hashes)} rule hashes from AGW output")
        logger.debug(f"Rule hashes: {rule_hashes}")
    else:
        logger.warning("No rule hashes found in AGW output")
    
    return rule_hashes


def verify_sim_policies_match_agw(sim_output: str, agw_rule_hashes: Set[str], policy_name: str) -> bool:
    """Verify that SIM policies contain the expected rule hashes from AGW"""
    assert sim_output, "SIM output is empty"
    assert agw_rule_hashes, "No AGW rule hashes provided"
    
    actual_data = json.loads(sim_output)
    actual_policies = actual_data.get("p_policy", {}).get("policies", [])
    assert actual_policies, "No policies found in SIM output"
    
    # Extract rule hashes from SIM policy names
    # SIM policy name format: "SmartSwitchNetworkPolicy/default/permit-all-simple/HASH/N"
    sim_rule_hashes = {
        match.group(1)
        for policy in actual_policies
        if (match := re.search(r'/([a-f0-9]{64})/', policy.get("name", "")))
    }
    assert sim_rule_hashes, "No rule hashes found in SIM policy names"
    
    # Compare the sets
    if agw_rule_hashes != sim_rule_hashes:
        missing_in_sim = agw_rule_hashes - sim_rule_hashes
        extra_in_sim = sim_rule_hashes - agw_rule_hashes
        
        error_parts = []
        if missing_in_sim:
            error_parts.append(f"Missing in SIM: {missing_in_sim}")
        if extra_in_sim:
            error_parts.append(f"Extra in SIM: {extra_in_sim}")
        
        raise AssertionError("; ".join(error_parts))
    
    logger.info(f"✅ All {len(agw_rule_hashes)} AGW rule hashes found in SIM policies")
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


def verify_rule_hashes_extracted(agw_output: str) -> Set[str]:
    rule_hashes = extract_rule_hashes_from_agw(agw_output)
    assert len(rule_hashes) > 0, "No rule hashes found in AGW output"
    logger.info(f"✅ Extracted {len(rule_hashes)} rule hashes from AGW")
    return rule_hashes


def verify_policy_in_sim_container(policy_name: str, sim_output: str, exact_match: bool = False) -> None:
    assert verify_policy_in_sim(policy_name, sim_output, exact_match=exact_match), \
        f"Policy '{policy_name}' not found in SIM dataplane"
    match_type = "exact" if exact_match else "case-insensitive"
    logger.info(f"✅ Policy '{policy_name}' found in SIM container ({match_type} match)")


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


def verify_sim_policy_structure(sim_output: str, expected_json_path: Path) -> bool:
    """Verify SIM policy structure matches expected JSON file"""
    assert sim_output, "SIM output is empty"
    
    # Load expected structure
    with open(expected_json_path, 'r') as f:
        expected_data = json.load(f)
    
    # Parse actual output
    actual_data = json.loads(sim_output)
    
    # Extract policies
    actual_policies = actual_data.get("p_policy", {}).get("policies", [])
    expected_policies = expected_data.get("p_policy", {}).get("policies", [])
    
    assert actual_policies, "No policies found in SIM output"
    assert expected_policies, "No policies found in expected JSON"
    
    # Compare policies
    _compare_policies(actual_policies, expected_policies)
    
    logger.info(f"✅ SIM policy structure matches expected ({len(actual_policies)} policies)")
    logger.debug(f"Actual policy names: {[p.get('name', 'N/A') for p in actual_policies]}")
    return True
