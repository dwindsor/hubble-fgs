// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package config

import (
	"io/ioutil"

	"github.com/isovalent/hubble-fgs/pkg/recorder"
	"sigs.k8s.io/yaml"
)

// Metadata for a GenericRecorderConf
type Metadata struct {
	Name string `yaml:"name"`
}

// GenericRecorderConf wraps a RecorderSpec so that it can be parsed from a CRD outside of
// the k8s API.
type GenericRecorderConf struct {
	ApiVersion string        `json:"apiVersion"`
	Kind       string        `json:"kind"`
	Metadata   Metadata      `json:"metadata"`
	Spec       recorder.Spec `json:"spec"`
}

// ReadConfigYaml reads out a GenericRecorderConf from a YAML string.
func ReadConfigYaml(data string) (*GenericRecorderConf, error) {
	var k GenericRecorderConf

	err := yaml.UnmarshalStrict([]byte(data), &k)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// FileConfigYaml reads out a GenericRecorderConf from a file.
func FileConfigYaml(fileName string) (*GenericRecorderConf, error) {
	config, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReadConfigYaml(string(config))
}
