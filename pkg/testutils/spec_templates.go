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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
)

// GetSpecFromTemplate creates a file bsed on the given template
func GetSpecFromTemplate(
	tmplname string,
	data interface{},
) (string, error) {
	_, testFname, _, _ := runtime.Caller(0)
	fname := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata", "specs", tmplname)
	tmpl, err := template.ParseFiles(fname)
	if err != nil {
		return "", err
	}

	tmpFilePattern := fmt.Sprintf("%s-*.yaml", strings.TrimSuffix(tmplname, ".yaml.tmpl"))
	tmpF, err := os.CreateTemp("", tmpFilePattern)
	if err != nil {
		return "", err
	}
	tmpName := tmpF.Name()

	err = tmpl.Execute(tmpF, data)
	if err != nil {
		tmpF.Close()
		os.Remove(tmpName)
		return "", err
	}

	tmpF.Close()
	os.Chmod(tmpName, 0644)
	return tmpName, nil
}
