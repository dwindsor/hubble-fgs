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

package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	enterprise "github.com/isovalent/hubble-fgs/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestEnterpriseYamlData(t *testing.T) {
	k, err := ReadConfigYaml(data)
	if err != nil {
		t.Errorf("YamlData error %s", err)
	}
	if reflect.DeepEqual(*k, expectedData) != true {
		t.Errorf("not equal\nk=%v\ne= %v\n", k, expectedData)
	}
}

var (
	tlsExample = `
apiVersion: hubble-enterprise.io/v1
metadata:
  name: "tls-example"
spec:
  parser:
    tls:
      mode: "tc"
`
)

func TestYamlTls(t *testing.T) {
	expected := GenericTracingConf{
		ApiVersion: "hubble-enterprise.io/v1",
		Metadata:   Metadata{Name: "tls-example"},
		Spec: enterprise.TracingPolicySpec{
			Parser: enterprise.ParserPolicySpec{
				Tls: enterprise.TlsSpec{
					Mode: "tc",
				},
			},
		},
	}

	k, err := ReadConfigYaml(tlsExample)
	if err != nil {
		t.Errorf("ReadConfigYaml failed: %s", err)
	}

	if reflect.DeepEqual(expected, *k) != true {
		t.Errorf("\ngot:\n%+v\nexpected:\n%+v", *k, expected)
	}
}

func TestEnterpriseExamplesSmoke(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	examplesDir := filepath.Join(filepath.Dir(filename), "../../crds/examples")
	err := filepath.Walk(examplesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip non-directories
		if info.IsDir() {
			return nil
		}

		// Skip non-yaml files with a warning
		if !strings.HasSuffix(info.Name(), "yaml") || strings.HasSuffix(info.Name(), "yml") {
			logger.GetLogger().WithField("path", path).Warn("skipping non-yaml file")
			return nil
		}

		// Fill this in with template data as needed
		data := map[string]string{
			"Pid": fmt.Sprint(os.Getpid()),
		}

		// Attempt to parse the file
		_, err = fileConfigWithTemplate(path, data)
		assert.NoError(t, err, "example %s must parse correctly", info.Name())

		return nil
	})

	assert.NoError(t, err, "failed to walk examples directory")
}
