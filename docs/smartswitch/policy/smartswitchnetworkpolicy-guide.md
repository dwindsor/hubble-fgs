# SmartSwitchNetworkPolicy Guide

This guide provides comprehensive documentation for the SmartSwitchNetworkPolicy custom resource definition (CRD), which enables Kubernetes-native network policy management for DPU-accelerated infrastructure. It covers policy structure, rule expansion, dataplane translation, and operational considerations.

## Resources

- **CRD Specification**: [IPA CRD YAML Spec](https://github.com/isovalent/ipa/blob/main/k8s/crds/isovalent.com/v1alpha1/isovalent.com_smartswitchnetworkpolicies.yaml)
- **Example Policies**: [SmartSwitchNetworkPolicyExamples](./smartswitchnetworkpolicy-examples.md)

## Table of Contents

- [Overview](#overview)
- [Policies vs. Rules](#policies-vs-rules)
  - [Understanding Policies](#understanding-policies)
  - [Understanding Rules](#understanding-rules)
  - [Rule Constraints](#rule-constraints)
- [Policy Names (ResourceIDs)](#policy-names-resourceids)
- [Rule Names](#rule-names)
- [Rule Limitations](#rule-limitations)
  - [Source Port Filtering Not Supported](#source-port-filtering-not-supported)
  - [Protocol and Port Filtering on Destination Only](#protocol-and-port-filtering-on-destination-only)
  - [No Inter-VRF or Inter-VLAN Traffic](#no-inter-vrf-or-inter-vlan-traffic)
- [Cartesian Product Expansion](#cartesian-product-expansion)
  - [Why Expansion is Needed](#why-expansion-is-needed)
  - [Expansion Formula](#expansion-formula)
  - [IP Family Matching](#ip-family-matching)
  - [Expansion Example](#expansion-example)
- [DPU Rule to Dataplane JSON Translation](#dpu-rule-to-dataplane-json-translation)
  - [JSON Structure](#json-structure)
  - [Understanding Rule Identification in the Dataplane](#understanding-rule-identification-in-the-dataplane)
- [Secure Policy Updates](#secure-policy-updates)
  - [Update Sequence](#update-sequence)
  - [Temporary Double Coverage](#temporary-double-coverage)
- [VRF Integration and Rule Activation](#vrf-integration-and-rule-activation)
  - [Dynamic VRF Lifecycle](#dynamic-vrf-lifecycle)
- [Multiple Policies in a Single File](#multiple-policies-in-a-single-file)
- [Examples](#examples)
  - [Policy Translation](#policy-translation)

## Overview

The system transforms high-level Kubernetes network policies into low-level DPU rules through a multi-stage pipeline:

```
K8s SmartSwitchNetworkPolicy → Internal SmartSwitchNetworkPolicy → PolicyRule → DPURule → JSON Dataplane Policy
```

Each Kubernetes policy can contain multiple rules, and each rule can expand to multiple internal policy objects based on the cartesian product of sources and destinations specified. Protocol/port combinations are kept together in each expanded policy rather than being expanded individually.

## Policies vs. Rules

### Understanding Policies

A **SmartSwitchNetworkPolicy** is a Kubernetes resource that acts as a container for one or more network policy rules. Each policy:

- Is a separate Kubernetes object with its own metadata (name, namespace, labels, annotations)
- Can contain one or more rules in its `spec.rules` array
- Is applied independently by the SmartSwitch controller
- Can be managed through standard Kubernetes operations (create, update, delete)

### Understanding Rules

A **rule** is an individual network policy specification within a policy that defines:

- A source network block
- A destination network block  
- Protocol and port filtering
- An action to take (allow or deny)
- An optional description

Each rule expands into multiple datapath rules based on the cross product of:
- Source IP blocks
- Destination IP blocks

Protocol/port combinations are attached to each expanded rule as an array rather than being expanded individually.

### Rule Constraints

**Protocol Requirements:**
- Every rule must specify at least one protocol in the `destination.protoPorts` field
- Port numbers are optional and can specify single ports or port ranges

**Logical Network Constraints:**
- Each IP block in source or destination can specify either a VRF or a VLAN, but not both
- If both VRF and VLAN are specified for the same IP block, the policy will be rejected
- IP blocks without VRF or VLAN apply to traffic not belonging to any logical network

## Policy Names (ResourceIDs)

Every applied policy is given a name defined as a **ResourceID**. A ResourceID is a composite identifier that uniquely identifies a Kubernetes policy resource within the cluster. It is created as a string of values extracted from the kubernetes custom resource object `<kind>/<namespace>/<name>`. For example, given the policy defined below, the ResourceID would be `SmartSwitchNetworkPolicy/default/api-access`.

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: api-access
  namespace: default
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
      destination:
        ipBlock:
          - cidr: "192.168.1.10/32"
        protoPorts:
          - protocol: "tcp"
            port: 8080
```

## Rule Names

Every expanded datapath rule is assigned a unique **RuleName** that combines a content-based hash with an auto-incremented numeric identifier. This ensures each rule can be uniquely identified and tracked as it flows through the system to DPU hardware.

### RuleName Format

A RuleName is constructed using the format `<hash>/<ruleID>`:

- **Hash**: A SHA-256 checksum of the expanded rule's content (CIDR, VRF, VLAN, ports, action)
- **RuleID**: An auto-incremented `uint32` value unique across all rules in the system

**Example**: `d4f6a8b2c9e1f3a5b7d9c2e4f6a8b1c3d5e7f9a1b3c5d7e9f1a3b5c7d9e1f3a5b7/123`

## Rule Limitations

SmartSwitchNetworkPolicy has the following constraints that affect how rules can be defined:

### Source Port Filtering Not Supported

Rules cannot filter traffic based on source port numbers. All rules apply to traffic from any source port. The source specification only supports IP blocks with optional VRF or VLAN identifiers - there is no `protoPorts` field available in the source section.

This limitation is enforced by the CRD schema itself: the source object does not provide any field for source port specification.

### Protocol and Port Filtering on Destination Only

Protocol and port filtering (via the `protoPorts` field) can only be specified on the destination side of a rule.

This is enforced by the CRD schema: `protoPorts` is a required field under `destination` but does not exist in the `source` definition.

### No Inter-VRF or Inter-VLAN Traffic

The system does not support rules that filter traffic crossing between different VRFs or between different VLANs. When you specify a VRF or VLAN in the source, the policy only applies to traffic that remains within that same logical network.

**Example of unsupported configuration:**
```yaml
source:
  ipBlock:
    - cidr: "10.0.0.0/8"
      vrf: "internal"
destination:
  ipBlock:
    - cidr: "192.168.0.0/16"
      vrf: "external"  # Different VRF - this rule will not work as intended
  protoPorts:
    - protocol: tcp
      port: 443
```

While the CRD schema allows you to specify different VRFs or VLANs between source and destination, the dataplane will not correctly enforce such rules. Both source and destination must belong to the same logical network (same VRF or same VLAN) for the rule to function correctly.

This limitation is **not enforced** by Kubernetes validation - the policy will be accepted but will not behave as expected in the dataplane.

> **Note:** Inter-VRF policy support is currently being implemented. This documentation will be updated when the feature becomes available.

## Cartesian Product Expansion

### Why Expansion is Needed

DPU Dataplane operates on atomic rules with single source and destination endpoints. A Kubernetes policy rule can specify multiple sources and destinations, requiring expansion into individual DPU rules. Protocol/port combinations are kept together as an array on each expanded rule.

### Expansion Formula

Given a rule with:
- **S** source IP blocks
- **D** destination IP blocks  

The number of generated internal policies is: **S × D**

Note that protocol/port combinations are **not** expanded—they remain as an array attached to each rule. This significantly reduces the total number of rules compared to a full cartesian expansion.

### IP Family Matching

During expansion, the system validates that source and destination IP addresses belong to the same IP family. Rules with mismatched IP families are automatically skipped:

- **IPv4 source → IPv6 destination**: Skipped (invalid)
- **IPv6 source → IPv4 destination**: Skipped (invalid)
- **IPv4 source → IPv4 destination**: Valid
- **IPv6 source → IPv6 destination**: Valid

This filtering happens silently during expansion—no error is raised, but the invalid combinations do not generate dataplane rules.

### Expansion Example

**Input Kubernetes Rule:**
```yaml
action: allow
source:
  ipBlock:
    - cidr: "10.0.1.0/24"
      vrf: "production"
    - cidr: "10.0.2.0/24"
      vrf: "production"
destination:
  ipBlock:
    - cidr: "192.168.1.100/32"
      vrf: "production"
    - cidr: "192.168.1.101/32"
      vrf: "production"
  protoPorts:
    - protocol: "TCP"
      port: 80
    - protocol: "TCP"
      port: 443
```

**Calculation:** 2 sources × 2 destinations = **4 internal policies**

**Generated Policies:**

1. `10.0.1.0/24 (production) → 192.168.1.100/32 (production) : [tcp/80, tcp/443]`
2. `10.0.1.0/24 (production) → 192.168.1.101/32 (production) : [tcp/80, tcp/443]`
3. `10.0.2.0/24 (production) → 192.168.1.100/32 (production) : [tcp/80, tcp/443]`
4. `10.0.2.0/24 (production) → 192.168.1.101/32 (production) : [tcp/80, tcp/443]`

Each of these becomes a separate DPU rule with its own unique hash and internal ID. Notice that protocol/port combinations are kept together as an array on each rule rather than being expanded.

## DPU Rule to Dataplane JSON Translation

After rules are generated from Kubernetes policies, they are translated into a DPU JSON format that the DPU Dataplane can consume. Each Dataplane JSON rule contains identification fields that establish a complete chain of traceability back to the originating Kubernetes resource.

### JSON Structure

The DPU JSON format contains the following fields:

```json
{
  "id": "<resourceVersion>:<k8sUid>:<policyName>:<ruleName>",
  "name": "<policyName>/<ruleName>",
  "operation": 0,
  "effect": "permit",
  "source": {
    "ip": "10.0.0.0/8",
    "port": [],
    "vlan": 100,
    "vrf": 1
  },
  "destination": {
    "ip": "192.168.1.0/24",
    "port": [
      {
        "port_low": 80,
        "port_high": 80,
        "protocol": ["tcp"]
      },
      {
        "port_low": 443,
        "port_high": 443,
        "protocol": ["tcp"]
      }
    ],
    "vlan": 200,
    "vrf": 0
  }
}
```

**Key Fields:**
- **operation**: `0` for UPSERT (add/update), `1` for DELETE
- **effect**: `"permit"` for allow rules, `"deny"` for deny rules
- **port**: An array of port objects, each containing `port_low`, `port_high`, and a `protocol` array
- **vrf**: Numeric VRF ID (resolved from VRF name at runtime)

**Port Merging:** When the same port range appears with multiple protocols (e.g., TCP and UDP on port 53), they are merged into a single port entry with multiple protocols in the `protocol` array.

### Understanding Rule Identification in the Dataplane

Every rule pushed to the DPU hardware carries two key identification fields that link it back to its Kubernetes origin: the `id` field and the `name` field. These fields are constructed from the PolicyName (ResourceID) and RuleName.

#### The ID Field

The `id` field serves as the primary traceability key, embedding four pieces of critical information separated by colons `<resource version>:<k8s uid>:<policy name>:<rule name>`.

**Resource Version**: The Kubernetes resource version number of the SmartSwitchNetworkPolicy. This changes each time the policy is updated in Kubernetes, allowing you to identify which version of the policy generated this rule.

**Kubernetes UID**: The Kubernetes UID of the SmartSwitchNetworkPolicy. This is a unique identifier assigned by Kubernetes when the policy is first created and remains constant throughout the policy's lifetime, even if the policy is modified.

**Policy Name**: The PolicyName, which is the ResourceID in the format `<kind>/<namespace>/<name>`. This identifies the specific Kubernetes policy object, including its type and location in the cluster.

**Rule Name**: The RuleName, consisting of the content-based SHA-256 hash followed by the auto-incremented internal rule ID. This identifies the specific expanded dataplane rule within all rules generated from that policy.

Together, these four components create a unique identifier that cannot collide across policies, policy versions, or individual rules. When examining a rule in the DPU Dataplane, the ID field provides all the context necessary to determine exactly which policy generated the JSON rule.

#### The Name Field

The `name` field provides a shortened, human-readable identifier by combining just the PolicyName and RuleName in the format `<policyName>/<ruleName>`. This field sacrifices the Kubernetes metadata (resource version and UID) for brevity, making it easier to read in logs and debugging output while still maintaining uniqueness across all rules in the system.

Since the RuleName includes both a content hash and an internal ID, and the PolicyName includes the full resource path, the name field is sufficient to uniquely identify a rule within the context of the current cluster state. However, it cannot trace rule history across policy updates the way the ID field can.

## Secure Policy Updates

The system ensures continuous policy enforcement during rule updates through a carefully orchestrated sequence of operations that prevents any window where traffic might bypass security policies.

### Update Sequence

When a policy is updated (for example, adding new ports or changing IP ranges), the system processes the change in a specific order:

1. **New rule generation**: The updated policy is expanded into its full set of dataplane rules, and each rule receives a new unique identifier
2. **Addition before deletion**: All new rules are added to the state and marked for UPSERT operations to the DPU
3. **Delayed removal**: Only after new rules are added are the old rules removed from the state and marked for DELETE operations
4. **Sequential submission**: The DPU receives UPSERT operations first, followed by DELETE operations

### Temporary Double Coverage

During policy updates, there's a brief period where both old and new rules are active simultaneously. This means:

- If a rule remains logically the same but the policy was updated, both versions exist briefly
- The DPU enforces both rule sets until the old rules are explicitly deleted
- This overlap ensures no traffic gaps—rules may be over-enforced momentarily but never under-enforced
- Once old rules are deleted, only the new rule set remains active

## VRF Integration and Rule Activation

Network policies reference VRFs by name, but the DPU Dataplane requires numeric VRF IDs to enforce rules. These VRF names are translated using a live mapping of active VRF names to IDs. As a result, **rules are only sent to the DPU dataplane when required VRF mappings are present on the switch.** This means:

- When you define a policy using VRF names like "internal" or "external", those rules are stored but not yet active
- The switch checks whether the VRF exists in the name to ID map
- Only when VRF exists and has a valid numeric ID are the rules converted and pushed to the DPU Dataplanes
- If a VRF is missing, the rules remain dormant until the network topology is updated

### Dynamic VRF Lifecycle

As the switch VRF map changes, rules automatically activate and deactivate based on VRF availability:

**When a new VRF is added to the switch:**
- The system identifies all policies that reference this VRF
- Rules that were previously dormant because this VRF was missing now become eligible
- This happens automatically without needing to re-apply the network policies

**When a VRF is removed from the switch:**
- All rules that depend on this VRF are immediately deleted from the DPU dataplane
- The rules remain defined in the system but are no longer enforced in the dataplane
- If the VRF is later re-added (even with a different numeric ID), the rules automatically reactivate

This dynamic behavior ensures that policy enforcement always matches the actual network topology. You cannot accidentally enforce rules that reference non-existent network segments, and rules automatically adapt as the network topology evolves.

## Multiple Policies in a Single File

You can define multiple SmartSwitchNetworkPolicy resources in a single YAML file by separating them with the YAML document separator `---`.

### Example

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-web-traffic
  namespace: production
spec:
  rules:
    - action: allow
      source:
        ipBlock:
          - cidr: 10.0.0.0/16
      destination:
        ipBlock:
          - cidr: 192.168.1.0/24
        protoPorts:
          - protocol: tcp
            port: 80
          - protocol: tcp
            port: 443
---
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: deny-internal-egress
  namespace: production
spec:
  rules:
    - action: deny
      description: Block access to internal admin network
      source:
        ipBlock:
          - cidr: 10.0.0.0/16
      destination:
        ipBlock:
          - cidr: 172.16.0.0/12
        protoPorts:
          - protocol: tcp
```

The triple-dash separator `---` tells YAML parsers that a new document is starting, allowing `kubectl` and other tools to process multiple resources in sequence.

## Examples

### Policy Translation

```yaml
apiVersion: isovalent.com/v1alpha1
kind: SmartSwitchNetworkPolicy
metadata:
  name: allow-dns
  namespace: production
spec:
  rules:
    - description: "Allow DNS queries to Google DNS"
      action: allow
      source:
        ipBlock:
          - cidr: "10.0.0.0/8"
            vrf: "internal"
      destination:
        ipBlock:
          - cidr: "8.8.8.8/32"
            vrf: "internal"
        protoPorts:
          - protocol: "udp"
            port: 53
```

#### ResourceID (PolicyName)

PolicyName: `SmartSwitchNetworkPolicy/production/allow-dns`

#### Cartesian Expansion

Formula: 1 source × 1 destination = 1 dataplane rule

#### RuleName

RuleName: `e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3/1001`

Consisting of:
- Hash: `e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3` (SHA-256 of the rule content)
- Internal ID: `1001` (auto-incremented system-wide identifier)

#### Dataplane JSON Fields

Dataplane JSON `id` field:
```
12345:a1b2c3d4-e5f6-7890-abcd-ef1234567890:SmartSwitchNetworkPolicy/production/allow-dns:e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3/1001
```

Consisting of:
- Resource Version: `12345`
- Kubernetes UID: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`
- PolicyName: `SmartSwitchNetworkPolicy/production/allow-dns`
- RuleName: `e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3/1001`

Dataplane JSON `name` field:
```
SmartSwitchNetworkPolicy/production/allow-dns/e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3/1001
```

Consisting of:
- PolicyName: `SmartSwitchNetworkPolicy/production/allow-dns`
- RuleName: `e7a4d8c2b5f9a1c3e5b7d9f2a4c6e8a1b3d5f7c9e1a3b5c7d9f1e3a5b7c9e1f3/1001`
