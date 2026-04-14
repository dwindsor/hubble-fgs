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
    verify_metrics_baseline,
    verify_metrics_consistent_with_policies,
    verify_metrics_error_counter_increased,
    verify_metrics_policy_counts,
    verify_metrics_no_errors,
    verify_policy_added_to_agw,
)
from helper.policy_generator import generate_policy_for_test, create_rule
from helper.utils import load_policy_yaml, wait_for_timeout


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Baseline Metrics")
@allure.title("Verify metrics with no policies loaded")
def test_metrics_baseline(cmd):
    """Verify metrics output when no policies are loaded.

    Checks:
    - All 7 JSON fields are present
    - policy_k8s_ids == 0
    - policy_dpu_rules == 0
    - All error counters are 0
    - Memory usage is positive
    - CPU usage is non-negative
    """
    with allure.step("Fetch metrics JSON with no policies loaded"):
        metrics = cmd.agw_metrics_show_json()

    with allure.step("Verify baseline metrics values"):
        verify_metrics_baseline(metrics)


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Policy Metrics")
@allure.title("Verify metrics through full policy add/remove lifecycle")
def test_metrics_policy_lifecycle(cmd):
    """Verify metrics track policy counts through a full lifecycle.

    Steps:
    1. Add policy-1 (1 rule) → verify k8s_ids=1, dpu_rules=1
    2. Add policy-2 (2 rules) → verify k8s_ids=2, dpu_rules=3
    3. Remove policy-1 → verify k8s_ids=1, dpu_rules=2
    4. Remove policy-2 → verify k8s_ids=0, dpu_rules=0
    Error counters are checked at every stage.
    """
    policy1_name = "metrics-lifecycle-1"
    policy1_rules = [
        create_rule(
            "10.1.0.0/16", "10.2.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
        )
    ]

    policy2_name = "metrics-lifecycle-2"
    policy2_rules = [
        create_rule(
            "10.3.0.0/16", "10.4.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
        ),
        create_rule(
            "10.5.0.0/16", "10.6.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
        ),
    ]

    # Step 1: Add first policy (1 rule)
    with allure.step(f"Add policy '{policy1_name}' (1 rule)"):
        _, policy1_file = generate_policy_for_test(policy1_name, policy1_rules)
        result = cmd.agw_add_policy(str(policy1_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy1_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify metrics: 1 policy, 1 rule"):
        metrics = cmd.agw_metrics_show_json()
        verify_metrics_policy_counts(metrics, expected_k8s_ids=1, expected_dpu_rules=1)
        verify_metrics_no_errors(metrics)

    # Step 2: Add second policy (2 rules)
    with allure.step(f"Add policy '{policy2_name}' (2 rules)"):
        _, policy2_file = generate_policy_for_test(policy2_name, policy2_rules)
        result = cmd.agw_add_policy(str(policy2_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(
            result, policy2_name, agw_policies, expected_policy_count=2
        )
        wait_for_timeout(2)

    with allure.step("Verify metrics: 2 policies, 3 rules"):
        metrics = cmd.agw_metrics_show_json()
        verify_metrics_policy_counts(metrics, expected_k8s_ids=2, expected_dpu_rules=3)
        verify_metrics_no_errors(metrics)

    # Step 3: Remove first policy
    with allure.step(f"Remove policy '{policy1_name}'"):
        cmd.agw_remove_policy(str(policy1_file))
        wait_for_timeout(2)

    with allure.step("Verify metrics: 1 policy, 2 rules"):
        metrics = cmd.agw_metrics_show_json()
        verify_metrics_policy_counts(metrics, expected_k8s_ids=1, expected_dpu_rules=2)
        verify_metrics_no_errors(metrics)

    # Step 4: Remove second policy
    with allure.step(f"Remove policy '{policy2_name}'"):
        cmd.agw_remove_policy(str(policy2_file))
        wait_for_timeout(2)

    with allure.step("Verify metrics: 0 policies, 0 rules"):
        metrics = cmd.agw_metrics_show_json()
        verify_metrics_policy_counts(metrics, expected_k8s_ids=0, expected_dpu_rules=0)
        verify_metrics_no_errors(metrics)


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Metrics Consistency")
@allure.title("Verify metrics DPU rule count matches policies show output")
def test_metrics_consistency_with_policies(cmd):
    """Verify metrics DPU rule count is consistent with agwctl policies show.

    Adds a multi-CIDR policy that expands to a known number of rules,
    then compares the DPU rule count from metrics against the actual
    rule count reported by agwctl policies show.
    """
    policy_name = "metrics-consistency-test"
    # 4 rules with distinct src/dst CIDRs = 4 expanded DPU rules
    rules = [
        create_rule(
            "10.10.0.0/16", "10.20.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 80)],
        ),
        create_rule(
            "10.10.0.0/16", "10.30.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 443)],
        ),
        create_rule(
            "10.11.0.0/16", "10.20.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("UDP", 53)],
        ),
        create_rule(
            "10.11.0.0/16", "10.30.0.0/16",
            source_vrf="default",
            dest_proto_ports=[("TCP", 22)],
        ),
    ]

    with allure.step("Add multi-rule policy"):
        _, policy_file = generate_policy_for_test(policy_name, rules)
        result = cmd.agw_add_policy(str(policy_file))
        agw_policies = cmd.agw_show_policies()
        verify_policy_added_to_agw(result, policy_name, agw_policies)
        wait_for_timeout(2)

    with allure.step("Verify metrics are consistent with policies show"):
        metrics = cmd.agw_metrics_show_json()
        policies_json = cmd.agw_show_policies_json()
        verify_metrics_consistent_with_policies(metrics, policies_json)
        verify_metrics_no_errors(metrics)


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Error Statistics")
@allure.title("Verify delete error counter increments on orphaned CRD deletion")
def test_error_counter_delete_orphaned_policy(cmd):
    """Trigger a DPU delete error by deleting a CRD whose policy was already
    cleared from AGW's internal store.

    The K8s watcher calls DeletePolicy on a resource ID that no longer exists
    in the repository, causing "policy with resource ID not found" error
    and incrementing policy_dpu_delete_errors.

    Steps:
    1. Apply a valid policy via kubectl (watcher adds it to AGW)
    2. Clear AGW's internal policy store via agwctl policies clear
    3. Record baseline delete error count
    4. Delete the CRD via kubectl (watcher tries to delete unknown policy)
    5. Verify delete error counter increased
    """
    policy_name = "orphaned-delete-test"
    valid_yaml = load_policy_yaml("valid_policy_simple.yaml", policy_name)

    try:
        with allure.step("Apply valid policy via kubectl"):
            cmd.kubectl_apply(valid_yaml)
            wait_for_timeout(5)

        with allure.step("Clear AGW internal policy store"):
            cmd.agw_clear_policies()
            wait_for_timeout(2)

        with allure.step("Record baseline delete error count"):
            metrics_before = cmd.agw_metrics_show_json()

        with allure.step("Delete CRD via kubectl (policy already cleared)"):
            cmd.kubectl_delete(valid_yaml)
            wait_for_timeout(5)

        with allure.step("Verify delete error counter increased"):
            metrics_after = cmd.agw_metrics_show_json()
            verify_metrics_error_counter_increased(
                metrics_before, metrics_after, "policy_dpu_delete_errors"
            )
    finally:
        with allure.step("Cleanup: ensure CRD is deleted"):
            cmd.kubectl_delete(valid_yaml)
            wait_for_timeout(2)


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Error Statistics")
@allure.title("Verify insert error counter increments on invalid policy via K8s")
def test_error_counter_insert_invalid_policy(cmd):
    """Trigger a DPU insert error by applying a policy with a missing CIDR
    field via kubectl to the kind cluster.

    The CRD allows an ipBlock item without a cidr field, but the Go-side
    ToSmartSwitchNetworkPolicies() fails when cidrIPFamily("") is called
    with an empty string, incrementing policy_dpu_insert_errors.

    Steps:
    1. Record baseline insert error count
    2. Apply an invalid SmartSwitchNetworkPolicy via kubectl
    3. Wait for the K8s watcher to process
    4. Verify insert error counter increased
    5. Cleanup: delete the invalid CRD
    """
    policy_name = "invalid-insert-test"
    invalid_yaml = load_policy_yaml("invalid_policy_missing_cidr.yaml", policy_name)

    with allure.step("Record baseline insert error count"):
        metrics_before = cmd.agw_metrics_show_json()

    try:
        with allure.step("Apply invalid policy via kubectl"):
            cmd.kubectl_apply(invalid_yaml)
            wait_for_timeout(5)

        with allure.step("Verify insert error counter increased"):
            metrics_after = cmd.agw_metrics_show_json()
            verify_metrics_error_counter_increased(
                metrics_before, metrics_after, "policy_dpu_insert_errors"
            )
    finally:
        with allure.step("Cleanup: delete invalid CRD"):
            cmd.kubectl_delete(invalid_yaml)
            wait_for_timeout(2)


@pytest.mark.agw
@pytest.mark.metrics
@allure.feature("Metrics")
@allure.story("Error Statistics")
@allure.title("Verify update error counter increments on invalid policy update via K8s")
def test_error_counter_update_invalid_policy(cmd):
    """Trigger a DPU update error by first applying a valid policy via kubectl,
    then updating it to have a missing CIDR field.

    Steps:
    1. Apply a valid policy via kubectl
    2. Wait for the K8s watcher to process it successfully
    3. Record baseline update error count
    4. Update the policy to have a missing CIDR (invalid for Go-side parsing)
    5. Wait and verify update error counter increased
    6. Cleanup
    """
    policy_name = "invalid-update-test"
    valid_yaml = load_policy_yaml("valid_policy_simple.yaml", policy_name)
    invalid_yaml = load_policy_yaml("invalid_policy_missing_cidr.yaml", policy_name)

    try:
        with allure.step("Apply valid policy via kubectl"):
            cmd.kubectl_apply(valid_yaml)
            wait_for_timeout(5)

        with allure.step("Record baseline update error count"):
            metrics_before = cmd.agw_metrics_show_json()

        with allure.step("Update policy to have missing CIDR"):
            cmd.kubectl_apply(invalid_yaml)
            wait_for_timeout(5)

        with allure.step("Verify update error counter increased"):
            metrics_after = cmd.agw_metrics_show_json()
            verify_metrics_error_counter_increased(
                metrics_before, metrics_after, "policy_dpu_update_errors"
            )
    finally:
        with allure.step("Cleanup: delete CRD"):
            cmd.kubectl_delete(valid_yaml)
            wait_for_timeout(2)

