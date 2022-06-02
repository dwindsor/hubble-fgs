//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package testutils

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/testutils"
)

// CreateExportFile creates an export file for a test.
// a callback will be registered at t.Cleanup() for closing the file, and removing the file
func CreateExportFile(t *testing.T) *os.File {
	return testutils.CreateExportFile(t)
}

// GetExportFilename return export filename for test
func GetExportFilename(t *testing.T) string {
	return testutils.GetExportFilename(t)
}

// KeepExportFile marks export file to be kept
func KeepExportFile(t *testing.T) {
	testutils.KeepExportFile(t)
}
