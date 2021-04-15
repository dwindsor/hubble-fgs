// Copyright 2020 Authors of Hubble
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

package observer

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/config"
	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/covalentio/hubble-fgs/pkg/logger"
)

// Sensors
//
// Sensors are a mechanism for dynamically loading/unloading bpf programs.
// Contrarily to low-level facilities like kprobes, sensors are meant to be
// visible to end users who can enable/disable them.
//
// Sensor control operations are done in a separate goroutine which acts as a
// serialization point for concurrent client requests.

var (
	// list of availableSensors, see registerSensor()
	availableSensors map[string]*observerSensor = map[string]*observerSensor{}
)

type sensorLoadArg struct {
	sttManagerHandle
}

type sensorUnloadArg = sensorLoadArg

// observerSensorIface is the interface to the underlying sensor implementations
type observerSensorImpl interface {
	sensorLoaded(arg sensorLoadArg)
	sensorUnloaded(arg sensorUnloadArg)

	sensorGetConfig(cfg string) (string, error)
	sensorSetConfig(cfg string, val string) error
}

// observerSensor is a set of bpf programs and maps that are managed as a unit.
//
// NB: For now we assume that sensors use disjoint sets of progs and maps.  If
// that assumption breaks, we need to be smarter about loading/deleting programs
// and maps (e.g., keep reference counts).
type observerSensor struct {
	name   string
	progs  []*bpfLoad
	maps   []*ObserverMap
	loaded bool
	impl   observerSensorImpl
}

// registerSensor registers a sensor so that it is available to users.
//
// This function is meant to be called in an init().
// This ensures that the function is called before controller goroutine starts,
// and that the availableSensors is setup without having to worry about
// synchronization.
func registerSensorAtInit(s *observerSensor) {

	if _, exists := availableSensors[s.name]; exists {
		panic(fmt.Sprintf("registerSensor called, but %s is already registered", s.name))
	}

	availableSensors[s.name] = s
}

// There are 6 commands that can be passed to the controller goroutine:
// - tracingPolicyAdd
// - sensorList
// - sensorEnable
// - sensorDisable
// - sensorRemove
// - sensorCtlStop

// tracingPolicyAdd adds a sensor based on a the provided tracing policy
type tracingPolicyAdd struct {
	ctx        context.Context
	sensorName string
	spec       *v1alpha1.TracingPolicySpec
	retChan    chan error
}

// sensorAdd adds a sensor
type sensorAdd struct {
	ctx     context.Context
	name    string
	sensor  *observerSensor
	retChan chan error
}

// sensorRemove removes a sensor (for now, used only for tracing policies)
type sensorRemove struct {
	ctx     context.Context
	name    string
	retChan chan error
}

// sensorEnable enables a sensor
type sensorEnable struct {
	ctx  context.Context
	name string
	sttManagerHandle
	retChan chan error
}

// sensorDisable disables a sensor
type sensorDisable struct {
	ctx  context.Context
	name string
	sttManagerHandle
	retChan chan error
}

// sensorList returns a list of the active sensors
type sensorList struct {
	ctx     context.Context
	result  *[]api.SensorStatus
	retChan chan error
}

// set a configuration option on a sensor
type sensorConfigSet struct {
	ctx     context.Context
	name    string
	key     string
	val     string
	retChan chan error
}

// get a configuration option on a sensor
type sensorConfigGet struct {
	ctx     context.Context
	name    string
	key     string
	val     string
	retChan chan error
}

// sensorCtlStop stops the controller
type sensorCtlStop struct {
	ctx     context.Context
	name    string
	retChan chan error
}

// sensorOp is an interface for the sensor operations.
// Not strictly needed but allows for better type checking.
type sensorOp interface {
	sensorOpDone(error)
}

// trivial sensorOpDone implementations for commands
func (s *tracingPolicyAdd) sensorOpDone(e error) { s.retChan <- e }
func (s *sensorAdd) sensorOpDone(e error)        { s.retChan <- e }
func (s *sensorRemove) sensorOpDone(e error)     { s.retChan <- e }
func (s *sensorEnable) sensorOpDone(e error)     { s.retChan <- e }
func (s *sensorDisable) sensorOpDone(e error)    { s.retChan <- e }
func (s *sensorList) sensorOpDone(e error)       { s.retChan <- e }
func (s *sensorConfigSet) sensorOpDone(e error)  { s.retChan <- e }
func (s *sensorConfigGet) sensorOpDone(e error)  { s.retChan <- e }
func (s *sensorCtlStop) sensorOpDone(e error)    { s.retChan <- e }

type sensorCtlHandle = chan<- sensorOp

// startSensorCtl initializes the sensorCtlHandle by spawning a
// sensor controller goroutine.
//
// The purpose of this goroutine is to serialize loading and unloading of
// sensors as requested from different goroutines (e.g., different GRPC
// clients).
//
// TODO: One issue here is that the goroutine needs a refence to the
// ObserverKprobe structure to call observerLoadSensor(). AFAICT, it is safe to
// call observerLoadSensor() from other goroutines. However, to make this
// obvious, we should factor the necessary data out of ObserverKprobe and avoid
// the need to keep reference to ObserverKprobe by the sensor controller
// goroutine.
func (k *ObserverKprobe) startSensorCtl() error {

	if k.ObserverSync.sensorCtlHandle != nil {
		return fmt.Errorf("failed to start sensor controller: channel already exists")
	}

	c := make(chan sensorOp)
	go func() {
		done := false
		for !done {
			op_ := <-c
			err := errors.New("BUG in SensorCtl: unset error value")
			switch op := op_.(type) {

			case *tracingPolicyAdd:
				var sensor *observerSensor
				if _, exists := availableSensors[op.sensorName]; exists {
					err = fmt.Errorf("sensor %s already exists", op.sensorName)
					break
				}
				sensor, err = k.getSensorFromTracingPolicy(op.spec)
				if err != nil {
					break
				}
				availableSensors[op.sensorName] = sensor
				err = nil

			case *sensorAdd:
				if _, exists := availableSensors[op.name]; exists {
					err = fmt.Errorf("sensor %s already exists", op.name)
					break
				}
				availableSensors[op.name] = op.sensor
				err = nil

			case *sensorRemove:
				sensor, exists := availableSensors[op.name]
				if !exists {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				if sensor.loaded {
					err = fmt.Errorf("sensor %s enabled, please disable it before removing", op.name)
					break
				}
				delete(availableSensors, op.name)
				err = nil

			case *sensorEnable:
				sensor := availableSensors[op.name]
				if sensor == nil {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}

				// NB: For now, we don't treat a sensor already loaded as an error
				// because that would complicate the client side, but we might have
				// to reconsider
				if sensor.loaded {
					logger.GetLogger().Infof("ignoring enableSensor %s since sensor is already enabled", sensor.name)
					err = nil
					break
				}
				err = k.observerLoadSensor(op.ctx, sensor)
				if err == nil && sensor.impl != nil {
					sensor.impl.sensorLoaded(sensorLoadArg{sttManagerHandle: op.sttManagerHandle})
				}

			case *sensorDisable:
				sensor := availableSensors[op.name]
				if sensor == nil {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				// NB: ditto as sensorEnable
				if !sensor.loaded {
					logger.GetLogger().Infof("ignoring disableSensor %s since sensor is not enabled", sensor.name)
					err = nil
					break
				}
				err = k.observerUnloadSensor(sensor, op.ctx)
				if err == nil && sensor.impl != nil {
					sensor.impl.sensorUnloaded(sensorUnloadArg{sttManagerHandle: op.sttManagerHandle})
				}

			case *sensorList:
				ret := make([]api.SensorStatus, 0, len(availableSensors))
				for n, s := range availableSensors {
					ret = append(ret, api.SensorStatus{n, s.loaded})
				}
				op.result = &ret
				err = nil

			case *sensorConfigSet:
				sensor := availableSensors[op.name]
				if sensor == nil {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				if sensor.impl == nil {
					err = fmt.Errorf("sensor %s does not support configuration", op.name)
					break
				}
				err = sensor.impl.sensorSetConfig(op.key, op.val)

			case *sensorConfigGet:
				sensor := availableSensors[op.name]
				if sensor == nil {
					err = fmt.Errorf("sensor %s does not exist", op.name)
					break
				}
				if sensor.impl == nil {
					err = fmt.Errorf("sensor %s does not support configuration", op.name)
					break
				}
				op.val, err = sensor.impl.sensorGetConfig(op.key)

			case *sensorCtlStop:
				logger.GetLogger().Debugf("stopping sensor controller...")
				done = true
				err = nil

			default:
				err = fmt.Errorf("unknown sensorOp: %v", op)
			}

			op_.sensorOpDone(err)
		}
	}()

	k.ObserverSync.sensorCtlHandle = c
	return nil
}

func (o *ObserverKprobe) getSensorFromTracingPolicy(spec *v1alpha1.TracingPolicySpec) (*observerSensor, error) {
	kprobes := spec.KProbes
	tracepoints := spec.Tracepoints
	if len(kprobes) > 0 && len(tracepoints) > 0 {
		// TODO: requires some refactoring (see also below)
		return nil, errors.New("tracing policies with both kprobes and tracepoints are not currently supported")
	} else if len(kprobes) > 0 {
		return o.addGenericKprobeSensors(kprobes, ObserverBTF)
	} else if len(tracepoints) > 0 {
		return o.createGenericTracepointSensor(tracepoints)
	} else {
		return nil, errors.New("empty tracing policy")
	}
}

func (o *ObserverKprobe) getSensorFromTracingPolicyString(yaml string) (*observerSensor, error) {
	cnf, err := config.ReadConfigYaml(yaml)
	if err != nil {
		return nil, err
	}
	return o.getSensorFromTracingPolicy(&cnf.Spec)

}

func (o *ObserverKprobe) getSensorFromTracingPolicyFname(fname string) (*observerSensor, error) {
	yamlData, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to read yaml file %s: %w", fname, err)
	}
	return o.getSensorFromTracingPolicyString(string(yamlData))
}

/*
 * Observer sensor operations
 */

// EnableSensor enables a sensor by name
func (h *ObserverSync) EnableSensor(ctx context.Context, name string) error {
	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorEnable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorEnable{
		ctx:              ctx,
		name:             name,
		sttManagerHandle: h.sttManagerHandle,
		retChan:          retc,
	}

	h.sensorCtlHandle <- op
	err := <-retc

	return err
}

// AddSensor adds a sensor
func (h *ObserverSync) AddSensor(ctx context.Context, name string, sensor *observerSensor) error {
	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorDisable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorAdd{
		ctx:     ctx,
		name:    name,
		sensor:  sensor,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	return <-retc
}

// DisableSensor disables a sensor by name
func (h *ObserverSync) DisableSensor(ctx context.Context, name string) error {
	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorDisable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorDisable{
		ctx:              ctx,
		name:             name,
		sttManagerHandle: h.sttManagerHandle,
		retChan:          retc,
	}

	h.sensorCtlHandle <- op
	return <-retc
}

func (h *ObserverSync) ListSensors(ctx context.Context) (*[]api.SensorStatus, error) {

	if h.sensorCtlHandle == nil {
		return nil, fmt.Errorf("ListSensors failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorList{
		ctx:     ctx,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	err := <-retc
	if err == nil {
		return op.result, nil
	} else {
		return nil, err
	}
}

func (h *ObserverSync) GetSensorConfig(ctx context.Context, name string, cfgkey string) (string, error) {

	if h.sensorCtlHandle == nil {
		return "", fmt.Errorf("SensorGetConfig failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorConfigGet{
		ctx:     ctx,
		name:    name,
		key:     cfgkey,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	err := <-retc
	if err == nil {
		return op.val, nil
	} else {
		return "", err
	}
}

func (h *ObserverSync) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {

	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorSetConfig failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorConfigSet{
		ctx:     ctx,
		name:    name,
		key:     cfgkey,
		val:     cfgval,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	return <-retc
}

// AddTracingPolicy adds a new sensor based on a tracing policy
func (h *ObserverSync) AddTracingPolicy(ctx context.Context, sensorName string, spec *v1alpha1.TracingPolicySpec) error {
	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorEnable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &tracingPolicyAdd{
		ctx:        ctx,
		sensorName: sensorName,
		spec:       spec,
		retChan:    retc,
	}

	h.sensorCtlHandle <- op
	err := <-retc

	return err
}

func (h *ObserverSync) RemoveSensor(ctx context.Context, sensorName string) error {
	if h.sensorCtlHandle == nil {
		return fmt.Errorf("SensorEnable failed, controller channel not initialized")
	}
	retc := make(chan error)
	op := &sensorRemove{
		ctx:     ctx,
		name:    sensorName,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	err := <-retc

	return err
}

func (h *ObserverSync) stopSensorCtl(ctx context.Context) error {
	retc := make(chan error)
	op := &sensorCtlStop{
		ctx:     ctx,
		retChan: retc,
	}

	h.sensorCtlHandle <- op
	return <-retc
}
