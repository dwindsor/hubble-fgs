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

	"gopkg.in/yaml.v2"
)

type Metadata struct {
	Name string
}

type Filter struct {
	Type  string
	Op    string
	Value string
}

type Arg struct {
	Type    string
	Meta    string
	Filters []Filter
}

type Function struct {
	Call    string
	Return  bool
	Syscall bool
	Args    []Arg
	Filters []Filter
}

type Kprobe struct {
	Function []Function
}

type Spec struct {
	Description string
	Kprobe      Kprobe
}

type GenericKprobeConfig struct {
	ApiVersion string `yaml:"apiVersion"`
	Metadata   Metadata
	Spec       Spec
}

func ReadConfigYaml(data string) (*GenericKprobeConfig, error) {
	var k GenericKprobeConfig

	err := yaml.Unmarshal([]byte(data), &k)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func FileConfigYaml(fileName string) (*GenericKprobeConfig, error) {
	config, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	return ReadConfigYaml(string(config))
}
