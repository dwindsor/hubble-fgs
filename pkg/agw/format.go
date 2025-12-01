package agw

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
)

func filterPolicyNames(policyNames []string, nameFilter string) []string {
	if nameFilter == "" || nameFilter == "{}" {
		return policyNames
	}
	filtered := make([]string, 0, len(policyNames))
	for _, name := range policyNames {
		if matchPolicyPattern(name, nameFilter) {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func formatNoPoliciesMessage(nameFilter string) string {
	if nameFilter != "" && nameFilter != "{}" {
		return fmt.Sprintf("No policies found matching '%s'", nameFilter)
	}
	return "No policies loaded\n"
}

func formatSummaryHeader(policyCount int, nameFilter string) string {
	var b strings.Builder
	b.WriteString("\n╔═══════════════════════════════════════════════════════════════╗\n")
	b.WriteString(fmt.Sprintf("║  Total Policies: %-44d ║\n", policyCount))
	if nameFilter != "" && nameFilter != "{}" {
		b.WriteString(fmt.Sprintf("║  Filter: %-52s ║\n", nameFilter))
	}
	b.WriteString("╚═══════════════════════════════════════════════════════════════╝\n\n")
	return b.String()
}

// formatSwitchPolicy formats a single switch policy with its resource ID and rules list
func formatSwitchPolicy(resourceID switchpolicy.ResourceID, rulesList switchpolicy.K8sRulesList) string {
	var b strings.Builder
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	b.WriteString(fmt.Sprintf("Policy: %s\n", resourceID.String()))
	b.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	b.WriteString(fmt.Sprintf("  Total Rules:    %d\n\n", len(rulesList)))

	for i, rule := range rulesList {
		b.WriteString(formatSwitchPolicyRule(i+1, rule, i < len(rulesList)-1))
	}
	b.WriteString("\n")
	return b.String()
}

// formatSwitchPolicyRule formats a single SmartSwitchNetworkPolicy rule
func formatSwitchPolicyRule(idx int, rule *switchpolicy.PolicyRule, addSpacer bool) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("  ┌─ Rule %d ─────────────────────────────────────────────────────\n", idx))

	// Format action
	action := formatAction(rule.SwitchPolicy)
	b.WriteString(fmt.Sprintf("  │ Action:      %s\n", action))

	// Format rule name if available
	if ruleName := rule.RuleName; ruleName != "" {
		b.WriteString(fmt.Sprintf("  │ Rule Name:   %s\n", ruleName))
	}

	b.WriteString("  │\n")

	// Format source and destination
	if rule.SwitchPolicy != nil {
		b.WriteString(formatSwitchSource(rule.SwitchPolicy.Source))
		b.WriteString(formatSwitchDestination(rule.SwitchPolicy.Destination))
	}

	b.WriteString("  └───────────────────────────────────────────────────────────────\n")
	if addSpacer {
		b.WriteString("  │\n")
	}
	return b.String()
}

// formatAction formats the action from a SmartSwitchNetworkPolicy
func formatAction(policy *switchpolicy.SmartSwitchNetworkPolicy) string {
	if policy == nil {
		return "<unknown>"
	}
	if policy.Action.EnforceAction.Allow {
		return "Allow"
	}
	if policy.Action.EnforceAction.Deny {
		return "Deny"
	}
	return "<unspecified>"
}

// formatSwitchSource formats the source endpoint information
func formatSwitchSource(source switchpolicy.SmartSwitchNetworkSource) string {
	var b strings.Builder
	b.WriteString("  │ Source:\n")

	if source.Endpoint.CIDR != "" {
		b.WriteString(fmt.Sprintf("  │   • CIDR: %s\n", source.Endpoint.CIDR))
	}
	if source.Endpoint.VRF != "" {
		b.WriteString(fmt.Sprintf("  │   • VRF: %s\n", source.Endpoint.VRF))
	}
	if source.Endpoint.VLAN > 0 {
		b.WriteString(fmt.Sprintf("  │   • VLAN: %d\n", source.Endpoint.VLAN))
	}

	b.WriteString("  │\n")
	return b.String()
}

// formatSwitchDestination formats the destination endpoint information
func formatSwitchDestination(dest switchpolicy.SmartSwitchNetworkDestination) string {
	var b strings.Builder
	b.WriteString("  │ Destination:\n")

	if dest.Endpoint.CIDR != "" {
		b.WriteString(fmt.Sprintf("  │   • CIDR: %s\n", dest.Endpoint.CIDR))
	}
	if dest.Endpoint.VRF != "" {
		b.WriteString(fmt.Sprintf("  │   • VRF: %s\n", dest.Endpoint.VRF))
	}
	if dest.Endpoint.VLAN > 0 {
		b.WriteString(fmt.Sprintf("  │   • VLAN: %d\n", dest.Endpoint.VLAN))
	}
	if dest.ProtoPorts != nil {
		for _, p := range *dest.ProtoPorts {
			if p.Protocol != 0 {
				b.WriteString(fmt.Sprintf("  │   • Protocol: %s\n", p.Protocol.String()))
			}
			if p.Port > 0 {
				if p.EndPort > 0 && p.EndPort != p.Port {
					b.WriteString(fmt.Sprintf("  │   • Ports: %d-%d\n", p.Port, p.EndPort))
				} else {
					b.WriteString(fmt.Sprintf("  │   • Port: %d\n", p.Port))
				}
			}
		}
	}

	b.WriteString("  │\n")
	return b.String()
}

// matchPolicyPattern checks if the given name matches the specified pattern.
// The pattern can be:
//   - An empty string or "{}", which matches all names.
//   - A regular expression (if it contains regex special characters).
//   - A wildcard pattern using '*' (case-insensitive).
//   - Patterns like "*abc*" match substrings.
//   - Patterns like "*abc" match suffixes.
//   - Patterns like "abc*" match prefixes.
//   - Patterns like "ab*cd" match names starting with "ab" and ending with "cd".
//   - Patterns with multiple '*' wildcards require all parts to appear in order.
//   - An exact match (case-insensitive) if no wildcards or regex characters are present.
//
// Returns true if the name matches the pattern, false otherwise.
func matchPolicyPattern(name, pattern string) bool {
	if pattern == "" || pattern == "{}" {
		return true
	}

	if isRegexPattern(pattern) {
		return matchRegex(name, pattern)
	}

	nameLower := strings.ToLower(name)
	patternLower := strings.ToLower(pattern)

	if !strings.Contains(patternLower, "*") {
		return nameLower == patternLower
	}

	return matchWildcardPattern(nameLower, patternLower)
}

func isRegexPattern(pattern string) bool {
	regexSpecialChars := []rune{'.', '^', '$', '[', ']', '(', ')', '+', '?', '{', '}', '|', '\\'}
	for _, ch := range pattern {
		for _, special := range regexSpecialChars {
			if ch == special {
				return true
			}
		}
	}
	return false
}

func matchRegex(name, pattern string) bool {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(name)
}

func matchWildcardPattern(nameLower, patternLower string) bool {
	parts := strings.Split(patternLower, "*")

	switch {
	case strings.HasPrefix(patternLower, "*") && strings.HasSuffix(patternLower, "*") && len(parts) > 2:
		substr := strings.Join(parts[1:len(parts)-1], "*")
		return strings.Contains(nameLower, substr)
	case strings.HasPrefix(patternLower, "*") && len(parts) == 2:
		suffix := parts[1]
		return strings.HasSuffix(nameLower, suffix)
	case strings.HasSuffix(patternLower, "*") && len(parts) == 2:
		prefix := parts[0]
		return strings.HasPrefix(nameLower, prefix)
	case len(parts) == 2:
		prefix := parts[0]
		suffix := parts[1]
		return strings.HasPrefix(nameLower, prefix) && strings.HasSuffix(nameLower, suffix)
	default:
		idx := 0
		for _, part := range parts {
			if part == "" {
				continue
			}
			pos := strings.Index(nameLower[idx:], part)
			if pos == -1 {
				return false
			}
			idx += pos + len(part)
		}
		return true
	}
}

// formatSwitchPoliciesJsonStringByName formats filtered policies as a JSON map string
// where the key is the ResourceID and the value is the array of rules
func formatSwitchPoliciesJsonStringByName(filteredNames []string, policyMap map[switchpolicy.ResourceID]switchpolicy.K8sRulesList) string {
	// Create a map to hold the matching policies
	policies := make(map[string]switchpolicy.K8sRulesList)

	// Iterate through policyMap and find matching policies
	for resourceID, rulesList := range policyMap {
		policyName := resourceID.String()

		// Check if this policy matches any of the filtered names
		for _, filteredName := range filteredNames {
			if policyName == filteredName {
				policies[policyName] = rulesList
				break
			}
		}
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(policies)
	if err != nil {
		return fmt.Sprintf(`{"error": "failed to marshal policies: %v"}`, err)
	}

	return string(jsonData)
}
