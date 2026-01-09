// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"context"
	"time"

	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/attempt"
	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
)

// SensorManager defines the sensor manager operations used by the mandate manager
// This is a subset of the server.observer interface used by the gRPC server. More methods can be
// added as needed.
type SensorManager interface {
	AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error
	DeleteTracingPolicy(ctx context.Context, name string, namespace string) error
	ConfigureTracingPolicy(_ context.Context, conf *tetragon.ConfigureTracingPolicyRequest) error
}

type AlertRuleManager interface {
	AddAlertRule(ar *v1alpha1.AlertRule) error
	DeleteAlertRule(name string)
}

type LoadedMandate struct {
	Version  string    `json:"version,omitempty"`
	LoadedAt time.Time `json:"loaded_at"`
	Checksum string    `json:"checksum"`
}

// Status is the status of the mandate manager
type Status struct {
	Conf    mandateconf.ManagerConf `json:"conf"`
	Running bool                    `json:"running"`
	Mandate *LoadedMandate          `json:"mandate,omitempty"`

	Log attempt.Attempts `json:"log,omitempty"`
}

type ConfArg struct {
	URL           *string
	RefreshPeriod *time.Duration
	Refresh       bool
}

// Manager is the external interface to the mandate manager
type Manager interface {
	// Start the manager goroutine that monitors the mandate file
	Start() error
	Stop() error
	Refresh()
	Configure(arg ConfArg) error
	Status() *Status
}
