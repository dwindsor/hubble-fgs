// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package utils

import (
	"os/exec"
	"path/filepath"
)

func FixupBinaryPathname(path string) string {
	// Use exec.LookPath to resolve the binary location
	resolvedPath, err := exec.LookPath(path)
	if err != nil {
		// If we can't resolve it, leave the original binary as-is
		return path
	}

	realPath, err := filepath.EvalSymlinks(resolvedPath)
	if err == nil {
		resolvedPath = realPath
	}

	return resolvedPath
}
