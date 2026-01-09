// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

// labelsForManaged returns the generic Tetragon labels plus ManagedBy label.
func labelsForManaged(name string) map[string]string {
	return map[string]string{
		"app.kubernetes.io/instance":   name,
		"app.kubernetes.io/name":       name,
		"app.kubernetes.io/managed-by": "tetragon-operator",
	}
}
