// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package paths

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	// VRF patterns
	vrfInstRegex = regexp.MustCompile(`Inst-list\[name=([^\]]+)\]`)
	vrfDomRegex  = regexp.MustCompile(`Dom-list\[name=([^\]]+)\]`)

	// DPU patterns
	dpuSlotRegex      = regexp.MustCompile(`DpuSlot-list\[id=(\d+)\]`)
	dpuNameRegex      = regexp.MustCompile(`Dpu-list\[name=([^\]]+)\]`)
	dpuModuleNumRegex = regexp.MustCompile(`Inst-list\[moduleNum=(\d+)\]`)

	// VLAN patterns
	vlanEncapRegex = regexp.MustCompile(`BD-list\[fabEncap=([^\]]+)\]`)
	vlanIdRegex    = regexp.MustCompile(`Vlan-list\[vlanId=([^\]]+)\]`)

	// HA patterns
	haPeerRegex = regexp.MustCompile(`(?:Peer-list\[id=([^\]]+)\]|HaPeer-list\[ipAddr=([^\]]+)\])`)

	// Service patterns
	serviceNameRegex = regexp.MustCompile(`Service-list\[name=([^\]]+)\]`)
	vlanServiceRegex = regexp.MustCompile(`VlanService-list\[vlanName=([^\]]+)\]`)
)

// ExtractVRFInstName extracts the VRF name from a gNMI path.
// Returns the VRF name and true if found, or empty string and false if not.
func ExtractVRFInstName(path string) (string, bool) {
	matches := vrfInstRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractVRFDomName extracts the VRF name from a gNMI path.
// Returns the VRF name and true if found, or empty string and false if not.
func ExtractVRFDomName(path string) (string, bool) {
	matches := vrfDomRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractDPUSlot extracts the DPU slot ID from a gNMI path.
// Returns the slot ID and true if found, or 0 and false if not.
func ExtractDPUSlot(path string) (int, bool) {
	matches := dpuSlotRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return 0, false
	}
	slot, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, false
	}
	return slot, true
}

// ExtractDPUName extracts the DPU name from a gNMI path.
// Returns the DPU name and true if found, or empty string and false if not.
func ExtractDPUName(path string) (string, bool) {
	matches := dpuNameRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractDPUModuleNum extracts the DPU module number from a gNMI path.
// Matches Inst-list[moduleNum=X] in DPU notification paths.
// Returns the module number and true if found, or 0 and false if not.
func ExtractDPUModuleNum(path string) (int, bool) {
	matches := dpuModuleNumRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return 0, false
	}
	moduleNum, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, false
	}
	return moduleNum, true
}

// ExtractVLANEncap extracts the VLAN encap (fabric encapsulation) from a gNMI path.
// Returns the encap string and true if found, or empty string and false if not.
func ExtractVLANEncap(path string) (string, bool) {
	matches := vlanEncapRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractVLANId extracts the VLAN ID from a gNMI path containing Vlan-list[vlanId=X].
// Returns the VLAN ID string and true if found, or empty string and false if not.
func ExtractVLANId(path string) (string, bool) {
	matches := vlanIdRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractHAPeerIP extracts the HA peer IP from a gNMI path.
// Returns the IP string and true if found, or empty string and false if not.
// Supports both Peer-list[id=X] and HaPeer-list[ipAddr=X] formats.
func ExtractHAPeerIP(path string) (string, bool) {
	matches := haPeerRegex.FindStringSubmatch(path)
	if len(matches) < 3 {
		return "", false
	}
	// matches[1] is from Peer-list[id=X], matches[2] is from HaPeer-list[ipAddr=X]
	if matches[1] != "" {
		return matches[1], true
	}
	if matches[2] != "" {
		return matches[2], true
	}
	return "", false
}

// ExtractServiceName extracts the service name from a gNMI path.
// Returns the service name and true if found, or empty string and false if not.
func ExtractServiceName(path string) (string, bool) {
	matches := serviceNameRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// ExtractVLANServiceName extracts the VLAN service name from a gNMI path.
// Returns the VLAN name and true if found, or empty string and false if not.
func ExtractVLANServiceName(path string) (string, bool) {
	matches := vlanServiceRegex.FindStringSubmatch(path)
	if len(matches) < 2 {
		return "", false
	}
	return matches[1], true
}

// IsVRFPath returns true if the path is related to VRF configuration.
func IsVRFPath(path string) bool {
	return strings.Contains(path, "inst-items/Inst-list")
}

// IsVLANPath returns true if the path is related to VLAN configuration.
func IsVLANPath(path string) bool {
	return strings.Contains(path, "bd-items/BD-list")
}

// IsDPUPath returns true if the path is related to DPU configuration.
func IsDPUPath(path string) bool {
	return strings.Contains(path, "dpu-items") || strings.Contains(path, "DpuSlot-list")
}

// IsHAPath returns true if the path is related to HA configuration.
func IsHAPath(path string) bool {
	return strings.Contains(path, "ha-items")
}

// IsDevicePath returns true if the path is related to device configuration.
func IsDevicePath(path string) bool {
	return strings.Contains(path, "scontroller-items")
}

// IsFWPolicyPath returns true if the path is related to firewall policy.
func IsFWPolicyPath(path string) bool {
	return strings.Contains(path, "fwpolicy-items")
}

// IsServiceRedirPath returns true if the path is related to service redirect.
func IsServiceRedirPath(path string) bool {
	return strings.Contains(path, "serviceredir-items")
}

// GetLastPathElement returns the last element of a gNMI path.
// For example, "System/inst-items/Inst-list[name=default]/dom-items" returns "dom-items".
func GetLastPathElement(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	// Remove key filter if present
	if idx := strings.Index(last, "["); idx > 0 {
		return last[:idx]
	}
	return last
}

// selectorRegex matches [key=value] patterns in gNMI paths.
var selectorRegex = regexp.MustCompile(`\[[^\]]+\]`)

// StripSelectors removes all [key=value] selectors from a gNMI path.
// For example: "System/Inst-list[name=default]/dom-items" -> "System/Inst-list/dom-items"
func StripSelectors(path string) string {
	return selectorRegex.ReplaceAllString(path, "")
}

// stripOrigin removes the origin prefix (e.g. "device:") and leading slash
// from a gNMI path so that paths with and without the prefix compare equally.
func stripOrigin(path string) string {
	if colonIdx := strings.Index(path, ":"); colonIdx > 0 {
		// Only treat it as an origin prefix if it appears before any '[' selector.
		if bracketIdx := strings.Index(path, "["); bracketIdx == -1 || colonIdx < bracketIdx {
			path = path[colonIdx+1:]
		}
	}
	return strings.TrimPrefix(path, "/")
}

// PathMatches checks if a notification path exactly matches a subscription path pattern.
// This handles gNMI paths where the notification may have selectors (e.g., [name=default])
// that are not present in the subscription pattern, and where the notification
// path may arrive without the "device:" origin prefix.
//
// For example:
//   - subscription: "device:/System/inst-items/Inst-list"
//   - notification: "System/inst-items/Inst-list[name=default]"
//   - returns: true
//
// Use PathMatchesPrefix when the notification may be a child path of the subscription.
func PathMatches(notificationPath, subscriptionPath string) bool {
	// Strip origin prefixes and selectors from both paths for comparison.
	strippedNotification := StripSelectors(stripOrigin(notificationPath))
	strippedSubscription := StripSelectors(stripOrigin(subscriptionPath))

	return strippedNotification == strippedSubscription
}

// PathMatchesPrefix checks if a notification path starts with a subscription path pattern.
// Use this for container/list paths where notifications may arrive for child paths
// (e.g., a delete notification for a child element of a subscribed container).
//
// For example:
//   - subscription: "device:/System/svcCont/svcCFwPol-items/SvcCFwPol-list"
//   - notification: "System/svcCont/svcCFwPol-items/SvcCFwPol-list[name=foo]/child"
//   - returns: true
func PathMatchesPrefix(notificationPath, subscriptionPath string) bool {
	// Strip origin prefixes and selectors from both paths for comparison.
	strippedNotification := StripSelectors(stripOrigin(notificationPath))
	strippedSubscription := StripSelectors(stripOrigin(subscriptionPath))

	return strings.HasPrefix(strippedNotification, strippedSubscription)
}
