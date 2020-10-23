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

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/logger"
)

// Sensors
//
// Sensors are a mechanism for dynamically loading/unloading bpf programs.
// Contrarily to low-level facilities like kprobes, sensors are meant to be
// visible to end users who can enable/disable them.
//
// Sensor control operations are done in a separate goroutine which acts as a
// serialiation point for concurrent client requests.

var (
	// list of availableSensors, see registerSensor()
	availableSensors map[string]*observerSensor = map[string]*observerSensor{}
)

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
}

// registerSensor registers a sensor so that it is available to users.
//
// This function is meant to be called in an init().
// This ensures that the function is called before controller goroutine starts,
// and that the availableSensors is setup without having to worry about
// synchronization.
func registerSensor(s *observerSensor) {

	if _, exists := availableSensors[s.name]; exists {
		panic(fmt.Sprintf("registerSensor called, but %s is already registered", s.name))
	}

	availableSensors[s.name] = s
}

// There are 4 commands that can be passed to the controller goroutine:
// - sensorEnable
// - sensorDisable
// - sensorList
// - sensorCtlStop

// sensorEnable enables a sensor
type sensorEnable struct {
	ctx     context.Context
	name    string
	retChan chan error
}

// sensorDisable disables a sensor
type sensorDisable struct {
	ctx     context.Context
	name    string
	retChan chan error
}

// sensorList returns a list of the active sensors
type sensorList struct {
	ctx     context.Context
	result  *[]api.SensorStatus
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
func (s *sensorEnable) sensorOpDone(e error)  { s.retChan <- e }
func (s *sensorDisable) sensorOpDone(e error) { s.retChan <- e }
func (s *sensorList) sensorOpDone(e error)    { s.retChan <- e }
func (s *sensorCtlStop) sensorOpDone(e error) { s.retChan <- e }

type sensorCtl = chan sensorOp

// initializeSensorCtl initializes the sensorCtl field of the observer.
//
// NB: This function still uses methods from ObserverKprobe. It should be
// possible to completely decouple it from ObserverKprobe but it does not seem
// to worth the effort at the moment.
func (k *ObserverKprobe) startSensorCtl() error {

	if k.sensorCtl != nil {
		return fmt.Errorf("failed to start sensor controller: channel already exists")
	}

	c := make(chan sensorOp)
	go func() {
		done := false
		for !done {
			op_ := <-c
			err := errors.New("BUG: unset error value")
			switch op := op_.(type) {
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

			case *sensorList:
				ret := make([]api.SensorStatus, 0, len(availableSensors))
				for n, s := range availableSensors {
					ret = append(ret, api.SensorStatus{n, s.loaded})
				}
				op.result = &ret
				err = nil

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

	k.sensorCtl = c
	return nil
}

/*
 * Observer sensor operations
 */

// EnableSensor enables a sensor by name
func (k *ObserverKprobe) EnableSensor(ctx context.Context, name string) error {
	if k.sensorCtl == nil {
		return fmt.Errorf("SensorEnable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorEnable{
		ctx:     ctx,
		name:    name,
		retChan: retc,
	}

	k.sensorCtl <- op
	return <-retc
}

// DisableSensor disables a sensor by name
func (k *ObserverKprobe) DisableSensor(ctx context.Context, name string) error {
	if k.sensorCtl == nil {
		return fmt.Errorf("SensorDisable failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorDisable{
		ctx:     ctx,
		name:    name,
		retChan: retc,
	}

	k.sensorCtl <- op
	return <-retc
}

func (k *ObserverKprobe) ListSensors(ctx context.Context) (*[]api.SensorStatus, error) {

	if k.sensorCtl == nil {
		return nil, fmt.Errorf("ListSensors failed, controller channel not initialized")
	}

	retc := make(chan error)
	op := &sensorList{
		ctx:     ctx,
		retChan: retc,
	}

	k.sensorCtl <- op
	err := <-retc
	if err == nil {
		return op.result, nil
	} else {
		return nil, err
	}
}

func (k *ObserverKprobe) stopSensorCtl(ctx context.Context) error {
	retc := make(chan error)
	op := &sensorCtlStop{
		ctx:     ctx,
		retChan: retc,
	}

	k.sensorCtl <- op
	return <-retc
}
