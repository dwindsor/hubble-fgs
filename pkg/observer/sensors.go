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

	"github.com/covalentio/hubble-fgs/pkg/logger"
)

/*
 * Sensor operations are done in a separate goroutine which acts as a
 * serialiation point for concurrent client requests.
 */

// SensorCtl is the interface to the sensor controller
type SensorCtl interface {
	SensorEnable(ctx context.Context, name string) error
	SensorDisable(ctx context.Context, name string) error
	SensorList(ctx context.Context) ([]string, error)

	stop()
}

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
	result  []string
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
func (k *ObserverKprobe) startSensorCtl(sensors map[string]*observerSensor) error {

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
				sensor := sensors[op.name]
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
				sensor := sensors[op.name]
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
				err = fmt.Errorf("NYI")

			case *sensorCtlStop:
				logger.GetLogger().Debugf("stopping sensor controller...")
				done = true
				err = nil
				break

			default:
				err = fmt.Errorf("unknown sensorOp: %v", op)
			}

			op_.sensorOpDone(err)
		}
	}()

	k.sensorCtl = c
	return nil
}

// EnableSensor enables a sensor by name
func (k *ObserverKprobe) EnableSensor(ctx context.Context, name string) error {
	if k.sensorCtl == nil {
		return fmt.Errorf("SensorEnable failed, channel not initialized")
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
		return fmt.Errorf("SensorDisable failed, channel not initialized")
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

func (k *ObserverKprobe) stopSensorCtl(ctx context.Context) error {
	retc := make(chan error)
	op := &sensorCtlStop{
		ctx:     ctx,
		retChan: retc,
	}

	k.sensorCtl <- op
	return <-retc
}
