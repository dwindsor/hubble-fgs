// Copyright 2021 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"io/ioutil"

	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"gopkg.in/yaml.v2"
)

type Metadata struct {
	Name string `yaml:"name"`
}

type GenericKprobeConfig struct {
	ApiVersion string                     `yaml:"apiVersion"`
	Metadata   Metadata                   `yaml:"metadata"`
	Spec       v1alpha1.TracingPolicySpec `yaml:"spec"`
}

func readConfigYaml(data string) (*GenericKprobeConfig, error) {
	var k GenericKprobeConfig

	err := yaml.Unmarshal([]byte(data), &k)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func fileConfig(fileName string) (*GenericKprobeConfig, error) {
	config, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return readConfigYaml(string(config))
}

func FileConfigSpec(fileName string) (*v1alpha1.TracingPolicySpec, error) {
	k, err := fileConfig(fileName)
	if err != nil {
		return nil, err
	}
	return &k.Spec, err
}

func FileConfigYaml(fileName string) (*GenericKprobeConfig, error) {
	return fileConfig(fileName)
}
