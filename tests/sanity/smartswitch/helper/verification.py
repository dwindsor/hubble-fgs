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
from typing import List, Optional

from scapy.sendrecv import AsyncSniffer

from .utils import wait_for_timeout, get_last_packet_from_sniffer
from .packet_utils import send_packet_and_sniff, get_sniffer_iface, create_sniffers
from .packet_verification import verify_packet_processed
from .packet_builder import build_packet
from .policy_models import vrf_name_to_id

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


def verify_policy_added_to_agw(result: str, policy_name: str, agw_output: str, expected_policy_count: int = 1) -> None:
    assert verify_command_success(result, "AGW add policy"), \
        f"AGW add policy command failed"
    assert "Policies added successfully" in result, \
        f"Expected success message but got: {result}"
    assert verify_policy_in_agw(policy_name, agw_output), \
        f"Policy '{policy_name}' not found in AGW policies output"
    assert f"Total Policies: {expected_policy_count}" in agw_output, \
        f"Expected {expected_policy_count} policy(ies) but got different count"
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
    wait_for_timeout(2)
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
    
    # Parse both outputs, filtered by policy name
    agw_rules = parse_agw_policies(agw_output, policy_name=policy_name)
    dpu_rules = parse_dpu_policies(dpu_output, policy_name=policy_name)
    
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


def verify_policy_not_in_agw(policy_name: str, agw_output: str) -> bool:
    if policy_name in agw_output:
        raise AssertionError(f"Policy '{policy_name}' should be removed but still found in AGW output")
    logger.info(f"✅ Policy '{policy_name}' confirmed removed from AGW")
    return True


def verify_policy_add_error(result: str, expected_error_substring: str) -> bool:
    if "Policies added successfully" in result:
        raise AssertionError(
            f"Expected policy add to fail but it succeeded. Output: {result}"
        )
    
    if expected_error_substring not in result:
        raise AssertionError(
            f"Expected error containing '{expected_error_substring}' but got: {result}"
        )
    
    logger.info(f"✅ Policy add correctly failed with expected error: {expected_error_substring}")
    return True


def send_and_verify_packets(
    packets: list,
    sniffers: List[AsyncSniffer],
    send_iface: str,
    max_retries: int = 2,
    failure_tolerance: float = 0.0,
    process_vrf: bool = False,
) -> None:
    """Send each generated packet and verify it was processed correctly."""
    ifaces = [get_sniffer_iface(s) for s in sniffers]

    passed = 0
    failed = 0

    for pkt_info in packets:
        is_transmitted = pkt_info.action == "allow"
        description = pkt_info.summary()

        success = False
        for attempt in range(1 + max_retries):
            fresh_sniffers = create_sniffers(ifaces)

            if attempt > 0:
                logger.info(f"RETRY {attempt}/{max_retries}: {description}")

            send_packet_and_sniff(pkt_info.packet, fresh_sniffers, send_iface, description)
            if process_vrf:
                dst_vrf_id = vrf_name_to_id(pkt_info.dst_vrf)
                if dst_vrf_id and dst_vrf_id > 1:
                    egress_pkt = get_last_packet_from_sniffer(fresh_sniffers)
                    if not egress_pkt:
                        logger.warning(
                            f"No first-pass packet captured for VRF processing: {description}"
                        )
                        continue
                    pkt_second_pass = build_packet()._update_dst_vrf(
                        pkt_info.packet.copy(),
                        egress_pkt,
                        dst_vrf_id,
                    )
                    send_packet_and_sniff(
                        pkt_second_pass,
                        fresh_sniffers,
                        send_iface,
                        f"{description} second-pass dst-vrf={pkt_info.dst_vrf}",
                    )

            result = verify_packet_processed(fresh_sniffers, pkt_info.packet, is_transmitted)
            if result:
                success = True
                break

        if success:
            passed += 1
            logger.info(f"PASS: {description}")
        else:
            failed += 1
            logger.error(f"FAIL (after {max_retries} retries): {description}")

    total = len(packets)
    max_allowed_failures = int(total * failure_tolerance)
    logger.info(
        f"Packet verification results: {passed} passed, {failed} failed "
        f"out of {total} (tolerance: {failure_tolerance:.0%}, "
        f"max allowed failures: {max_allowed_failures})"
    )
    assert failed <= max_allowed_failures, (
        f"{failed} out of {total} packets failed verification "
        f"(exceeds {failure_tolerance:.0%} tolerance of {max_allowed_failures} allowed failures)"
    )
# Metrics JSON field names matching CurrentMetrics in switchmetrics/metrics.go
METRICS_FIELDS = [
    "total_physical_memory_kb_usage",
    "cpu_usage_percent",
    "policy_k8s_ids",
    "policy_dpu_rules",
    "policy_dpu_insert_errors",
    "policy_dpu_delete_errors",
    "policy_dpu_update_errors",
]


def verify_metrics_fields_present(metrics: dict) -> None:
    """Verify all expected JSON fields are present in metrics output."""
    missing = [f for f in METRICS_FIELDS if f not in metrics]
    if missing:
        raise AssertionError(f"Missing metrics fields: {missing}")
    logger.info(f"✅ All {len(METRICS_FIELDS)} metrics fields present")


def verify_metrics_baseline(metrics: dict) -> None:
    """Verify metrics values when no policies are loaded.

    Note: Error counters are cumulative and persist across AGW restarts,
    so they are not checked here. Use the dedicated error injection tests
    to verify error counter behavior.
    """
    verify_metrics_fields_present(metrics)

    assert metrics["policy_k8s_ids"] == 0, (
        f"Expected 0 policy K8s IDs, got {metrics['policy_k8s_ids']}"
    )
    assert metrics["policy_dpu_rules"] == 0, (
        f"Expected 0 DPU rules, got {metrics['policy_dpu_rules']}"
    )
    assert metrics["total_physical_memory_kb_usage"] > 0, (
        f"Expected positive memory usage, got {metrics['total_physical_memory_kb_usage']}"
    )
    assert metrics["cpu_usage_percent"] >= 0, (
        f"Expected non-negative CPU usage, got {metrics['cpu_usage_percent']}"
    )
    logger.info("✅ Baseline metrics verified (no policies, positive memory)")


def verify_metrics_policy_counts(
    metrics: dict,
    expected_k8s_ids: int,
    expected_dpu_rules: Optional[int] = None,
    min_dpu_rules: Optional[int] = None,
) -> None:
    """Verify policy-related metric counts."""
    verify_metrics_fields_present(metrics)

    assert metrics["policy_k8s_ids"] == expected_k8s_ids, (
        f"Expected {expected_k8s_ids} policy K8s IDs, got {metrics['policy_k8s_ids']}"
    )
    if expected_dpu_rules is not None:
        assert metrics["policy_dpu_rules"] == expected_dpu_rules, (
            f"Expected {expected_dpu_rules} DPU rules, got {metrics['policy_dpu_rules']}"
        )
    if min_dpu_rules is not None:
        assert metrics["policy_dpu_rules"] >= min_dpu_rules, (
            f"Expected at least {min_dpu_rules} DPU rules, got {metrics['policy_dpu_rules']}"
        )
    logger.info(
        f"✅ Metrics policy counts verified: k8s_ids={metrics['policy_k8s_ids']}, "
        f"dpu_rules={metrics['policy_dpu_rules']}"
    )


def verify_metrics_no_errors(metrics: dict, baseline_metrics: dict = None) -> None:
    """Verify error counters did not increase since baseline.

    If baseline_metrics is provided, asserts that each error counter has not
    increased. If no baseline is provided, just logs the current values
    (error counters are cumulative and persist across AGW restarts).
    """
    verify_metrics_fields_present(metrics)

    error_fields = ["policy_dpu_insert_errors", "policy_dpu_update_errors", "policy_dpu_delete_errors"]
    if baseline_metrics is not None:
        for field in error_fields:
            assert metrics[field] <= baseline_metrics[field], (
                f"Error counter {field} increased: {baseline_metrics[field]} -> {metrics[field]}"
            )
        logger.info("✅ Error counters did not increase since baseline")
    else:
        for field in error_fields:
            logger.info(f"  {field} = {metrics[field]}")
        logger.info("✅ Error counters logged (no baseline to compare)")


def verify_metrics_error_counts(
    metrics: dict,
    expected_insert_errors: int = 0,
    expected_update_errors: int = 0,
    expected_delete_errors: int = 0,
) -> None:
    """Verify error counters match specific expected values."""
    verify_metrics_fields_present(metrics)

    assert metrics["policy_dpu_insert_errors"] == expected_insert_errors, (
        f"Expected {expected_insert_errors} insert errors, "
        f"got {metrics['policy_dpu_insert_errors']}"
    )
    assert metrics["policy_dpu_update_errors"] == expected_update_errors, (
        f"Expected {expected_update_errors} update errors, "
        f"got {metrics['policy_dpu_update_errors']}"
    )
    assert metrics["policy_dpu_delete_errors"] == expected_delete_errors, (
        f"Expected {expected_delete_errors} delete errors, "
        f"got {metrics['policy_dpu_delete_errors']}"
    )
    logger.info(
        f"✅ Error counts verified: insert={expected_insert_errors}, "
        f"update={expected_update_errors}, delete={expected_delete_errors}"
    )


def verify_metrics_errors_stable(metrics_before: dict, metrics_after: dict) -> None:
    """Verify error counters did not change between two metric snapshots."""
    for field in ["policy_dpu_insert_errors", "policy_dpu_update_errors", "policy_dpu_delete_errors"]:
        assert metrics_before[field] == metrics_after[field], (
            f"{field} changed: {metrics_before[field]} → {metrics_after[field]}"
        )
    logger.info("✅ Error counters are stable (no change between snapshots)")


def verify_metrics_error_counter_increased(
    metrics_before: dict,
    metrics_after: dict,
    error_field: str,
) -> None:
    """Verify that a specific error counter increased between two snapshots.

    Args:
        metrics_before: Metrics snapshot taken before the error-inducing action.
        metrics_after: Metrics snapshot taken after the error-inducing action.
        error_field: The metrics field name to check
            (e.g. "policy_dpu_insert_errors").
    """
    before = metrics_before[error_field]
    after = metrics_after[error_field]
    assert after > before, (
        f"Expected {error_field} to increase: {before} -> {after}"
    )
    logger.info(
        f"✅ {error_field} increased as expected: {before} -> {after}"
    )


def verify_metrics_consistent_with_policies(
    metrics: dict,
    policies_json: dict,
) -> None:
    """Verify metrics policy counts match the actual policies show JSON output.

    Compares policy_k8s_ids against the number of policy entries and
    policy_dpu_rules against the total number of rules across all policies.
    """
    verify_metrics_fields_present(metrics)

    policies_data = policies_json.get("data", policies_json)
    expected_k8s_ids = len(policies_data)
    expected_dpu_rules = sum(len(rules) for rules in policies_data.values())

    assert metrics["policy_k8s_ids"] == expected_k8s_ids, (
        f"Metrics policy_k8s_ids ({metrics['policy_k8s_ids']}) != "
        f"policies show count ({expected_k8s_ids})"
    )
    assert metrics["policy_dpu_rules"] == expected_dpu_rules, (
        f"Metrics policy_dpu_rules ({metrics['policy_dpu_rules']}) != "
        f"policies show rules ({expected_dpu_rules})"
    )
    logger.info(
        f"✅ Metrics consistent with policies show: "
        f"k8s_ids={expected_k8s_ids}, dpu_rules={expected_dpu_rules}"
    )


