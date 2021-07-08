//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//
package btf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/config"
)

func expectError(t *testing.T, err error) error {
	if err == nil {
		return errors.New("validation should have failed, but did not")
	}
	// NB: eventually it would be good if we check that the error the
	// specific error we expect. For now, we just print the erorr so that
	// we can  inspect it.
	t.Logf("Got an error as expected: %s", err)
	return nil
}
func expectOK(t *testing.T, err error) error {
	if err != nil {
		return err
	}
	return nil
}

var testFiles = []struct {
	specFname string
	checkFn   func(t *testing.T, err error) error
}{
	{specFname: "specs/nosuchcall.yaml", checkFn: expectError},
	{specFname: "specs/notasyscall.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/syswrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/syslseek.yaml", checkFn: expectOK},
	{specFname: "specs/wrongargindex.yaml", checkFn: expectError},
	{specFname: "specs/wrongargtype.yaml", checkFn: expectError},
	{specFname: "specs/lseek.yaml", checkFn: expectOK},
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
	/* {specFname: "specs/wrongrettype.yaml", checkFn: expectError}, */
}

func TestSpecs(t *testing.T) {
	_, testFname, _, _ := runtime.Caller(0)
	testdataPath := filepath.Join(filepath.Dir(testFname), "..", "..", "testdata")

	// NB: for now we check against a single BTF file.
	btfFname := filepath.Join(testdataPath, "btf", "vmlinux-5.4.104+")
	if _, err := os.Stat(btfFname); err != nil {
		t.Skip(fmt.Sprintf("%s not found. Consider running 'make fetch-testdata'", btfFname))
	}
	btf, err := bpf.NewBTF(btfFname)
	if err != nil {
		t.Fatalf("failed to initialize BTF: %s", err)
	}
	defer btf.Close()

	for fi := range testFiles {
		specFname := testFiles[fi].specFname
		t.Run(specFname, func(t *testing.T) {
			specFname := filepath.Join(testdataPath, specFname)
			spec, err := config.FileConfigSpec(specFname)
			if err != nil {
				t.Fatal(err)
			}
			for ki := range spec.KProbes {
				err = ValidateKprobeSpec(btf, &spec.KProbes[ki])
				if checkErr := testFiles[fi].checkFn(t, err); checkErr != nil {
					t.Fatal(checkErr)
				}
			}
		})
	}
}
