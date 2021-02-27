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
