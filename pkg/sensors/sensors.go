//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sensors

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
)

var (
	AllPrograms = []*Program{
		&Execve,
		&Exit,
		&Fork,
		&Cred,
		&TCPConnect,
		&TCPConnectRet,
		&TCPClose,
		&TCPSendCheck,
		&Listen,
	}

	AllMaps = []*Map{
		&SocketMap,
		&ExecveMap,
		&TCPMonMap,
		&ExecveStats,
		&SocketStats,
		&TLSMapStats,
		&CiliumSNAT,
		&TCPSendCheckSampler,
	}
)

// GetInitialSensor returns the collection of Sensor that is loaded at
// initialization time.
func GetInitialSensor() *Sensor {
	progs := []*Program{
		&Execve,
		&Exit,
		&Fork,
		&Cred,
		&TCPConnect,
		&TCPConnectRet,
		&TCPClose,
		&TCPSendCheck,
		&Listen,
	}

	maps := []*Map{
		&TCPMonMap,
		&ExecveMap,
		&SocketMap,
		/* &ObserverTcpMap */
		&ExecveStats,
		&SocketStats,
		&TLSMapStats, // NB: Maybe this should be under k.enableTLS?
		&TCPSendCheckSampler,
	}

	return &Sensor{
		Name:  "__main__",
		Progs: progs,
		Maps:  maps,
	}
}

// Sensors
//
// Sensors are a mechanism for dynamically loading/unloading bpf programs.
// Contrarily to low-level facilities like kprobes, sensors are meant to be
// visible to end users who can enable/disable them.
//
// Sensor control operations are done in a separate goroutine which acts as a
// serialization point for concurrent client requests.

// Sensor is a set of BPF programs and maps that are managed as a unit.
//
// NB: For now we assume that sensors use disjoint sets of progs and maps.  If
// that assumption breaks, we need to be smarter about loading/deleting programs
// and maps (e.g., keep reference counts).
type Sensor struct {
	// Name is a human-readbale description.
	Name string
	// Progs are all the BPF programs that exist on the filesystem.
	Progs []*Program
	// Maps are all the BPF Maps that the progs use.
	Maps []*Map
	// Loaded indicates whether the sensor has been Loaded.
	Loaded bool
	// Ops contains an implementation to perform on this sensor.
	Ops Operations
}

// Operations is the interface to the underlying sensor implementations.
type Operations interface {
	Loaded(arg LoadArg)
	Unloaded(arg UnloadArg)

	GetConfig(cfg string) (string, error)
	SetConfig(cfg string, val string) error
}

func SensorCombine(name string, a, b *Sensor) *Sensor {
	if a != nil && b != nil {
		progs := append(a.Progs, b.Progs...)
		maps := append(a.Maps, b.Maps...)
		return SensorBuilder(name, progs, maps)
	} else if a != nil {
		return a
	} else if b != nil {
		return b
	}
	return nil
}

func SensorBuilder(name string, p []*Program, m []*Map) *Sensor {
	return &Sensor{
		Name:  name,
		Progs: p,
		Maps:  m,
	}
}

var (
	// list of availableSensors, see registerSensor()
	availableSensors map[string]*Sensor = map[string]*Sensor{}
	// list of registered Tracing handlers, see registerTracingHandler()
	registeredTracingSensors map[string]tracingSensor = map[string]tracingSensor{}
	// list of registers loaders, see registerProbeType()
	registeredProbeLoad map[string]tracingSensor = map[string]tracingSensor{}

	manager *Manager
)

// RegisterTracingSensorsAtInit registers a handler for Tracing policy.
//
// This function is meant to be called in an init().
// This will register a CRD or config file handler so that the config file
// or CRDs will be passed to the handler to be parsed.
func RegisterTracingSensorsAtInit(name string, s tracingSensor) {
	if _, exists := availableSensors[name]; exists {
		panic(fmt.Sprintf("RegisterTracingSensor called, but %s is already registered", name))
	}
	registeredTracingSensors[name] = s
}

// RegisterProbeType registers a handler for a probe type string
//
// This function is meant to be called in an init() by sensors that
// need extra logic when loading a specific probe type.
func RegisterProbeType(probeType string, s tracingSensor) {
	if _, exists := registeredProbeLoad[probeType]; exists {
		panic(fmt.Sprintf("RegisterProbeType called, but %s is already registered", probeType))
	}
	registeredProbeLoad[probeType] = s
}

type tracingSensor interface {
	SpecHandler(spec *v1alpha1.TracingPolicySpec) (*Sensor, error)
	LoadProbe(args LoadProbeArgs) (error, int)
}

// LoadProbeArgs are the args to the LoadProbe function.
type LoadProbeArgs struct {
	BPFDir, MapDir, CiliumDir string
	Load                      *Program
	Version, Verbose          int
	X64                       bool
}

// registerSensor registers a sensor so that it is available to users.
//
// This function is meant to be called in an init().
// This ensures that the function is called before controller goroutine starts,
// and that the availableSensors is setup without having to worry about
// synchronization.
func RegisterSensorAtInit(s *Sensor) {
	if _, exists := availableSensors[s.Name]; exists {
		panic(fmt.Sprintf("registerSensor called, but %s is already registered", s.Name))
	}

	availableSensors[s.Name] = s
}

// func GetSensorsFromParserPolicy(spec *v1alpha1.TracingPolicySpec) (*Sensor, error) {
// 	return sockmap.AddParserSensors(spec.Parser)
// }
