// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package policystatus

import (
	"regexp"

	"github.com/cilium/tetragon/pkg/logger"
)

var (
	// policyNameRegex captures the name part from "kind/namespace/name" format
	policyNameRegex = regexp.MustCompile(`^[^/]+/[^/]+/(.+)$`)
)

// extractPolicyNameFromPath extracts the policy name from a path in format "kind/namespace/name"
// Returns the name (third part) or the full string if the format is invalid
func extractPolicyNameFromPath(policyPath string) string {
	if policyPath == "" {
		return ""
	}

	// Use regex to extract the name part after the second slash
	matches := policyNameRegex.FindStringSubmatch(policyPath)

	// If regex matches, return the captured group (the name)
	if len(matches) == 2 {
		name := matches[1]
		logger.GetLogger().Debug("extracted policy name from path using regex",
			"policyPath", policyPath,
			"extractedName", name)
		return name
	}

	// Return original if format doesn't match expected pattern
	logger.GetLogger().Error("policy path format invalid, expected 'kind/namespace/name'",
		"policyPath", policyPath)
	return policyPath
}