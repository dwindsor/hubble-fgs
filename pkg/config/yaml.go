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
	"io/ioutil"

	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"sigs.k8s.io/yaml"
)

type Metadata struct {
	Name string `yaml:"name"`
}

type GenericTracingConf struct {
	ApiVersion string                     `json:"apiVersion"`
	Kind       string                     `json:"kind"`
	Metadata   Metadata                   `json:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `json:"spec"`
}

func ReadConfigYaml(data string) (*GenericTracingConf, error) {
	var k GenericTracingConf

	err := yaml.UnmarshalStrict([]byte(data), &k)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func fileConfig(fileName string) (*GenericTracingConf, error) {
	config, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReadConfigYaml(string(config))
}

func FileConfigSpec(fileName string) (*v1alpha1.TracingPolicySpec, error) {
	k, err := fileConfig(fileName)
	if err != nil {
		return nil, err
	}
	return &k.Spec, err
}

func FileConfigYaml(fileName string) (*GenericTracingConf, error) {
	return fileConfig(fileName)
}
