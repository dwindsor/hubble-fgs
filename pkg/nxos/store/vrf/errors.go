// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package vrf

import "fmt"

// ErrNotFound is returned when an operation is attempted on a non-existent VRF.
type ErrNotFound struct {
	Name string
}

func (e *ErrNotFound) Error() string {
	return fmt.Sprintf("VRF not found: %s", e.Name)
}

// IsNotFound returns true if the error indicates a VRF was not found.
func IsNotFound(err error) bool {
	_, ok := err.(*ErrNotFound)
	return ok
}
