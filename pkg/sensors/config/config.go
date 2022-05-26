package config

import (
	"context"
	"fmt"
	"os"

	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/isovalent/hubble-fgs/pkg/config"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
)

func createConfigSensors(configFile string) ([]*sensors.Sensor, error) {
	if configFile == "" {
		return nil, nil
	}

	yamlData, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", configFile, err)
	}
	cnf, err := config.ReadConfigYaml(string(yamlData))
	if err != nil {
		return nil, err
	}

	return sensors.GetSensorsFromParserPolicy(&cnf.Spec)
}

func mergeSensors(sens []*sensors.Sensor) *sensors.Sensor {
	var progs []*program.Program
	var maps []*program.Map

	for _, s := range sens {
		progs = append(progs, s.Progs...)
		maps = append(maps, s.Maps...)
	}
	return &sensors.Sensor{
		Name:  "__main__",
		Progs: progs,
		Maps:  maps,
	}
}

// LoadConfig loads the default sensor, including any from the configuration file.
func LoadConfig(ctx context.Context, bpfDir, mapDir, ciliumDir, configFile string) error {
	configSensors, err := createConfigSensors(configFile)
	if err != nil {
		return err
	}
	load := mergeSensors(configSensors)

	if err := load.Load(ctx, bpfDir, mapDir, ciliumDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}

	return nil
}
