// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package library

// ConfigNotFoundError represents an error when a configuration is not found
type ConfigNotFoundError struct{}

// Error implements the error interface
func (e *ConfigNotFoundError) Error() string {
	return "config not found"
}

// IsConfigNotFound checks if an error is a ConfigNotFoundError
func IsConfigNotFound(err error) bool {
	_, ok := err.(*ConfigNotFoundError)
	return ok
}
