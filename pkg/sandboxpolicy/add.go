// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func AddSandboxPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager, obj any) error {
	var tp tracingpolicy.TracingPolicy

	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		var err error
		log = log.With("sandbox-policy-name", sp.Name)
		tp, err = ToTracingPolicy(sp)
		if err != nil {
			log.Warn("AddSandboxPolicy: failed to convert to tracing policy", logfields.Error, err)
			return fmt.Errorf("failed to convert sandboxpolicy to tracing policy: %w", err)
		}

	case *v1alpha1.SandboxPolicyNamespaced:
		var err error
		log = log.With("sandbox-policy-name", sp.Name, "sandbox-policy-namespace", sp.Namespace)
		tp, err = ToTracingPolicyNamespaced(sp)
		if err != nil {
			log.Warn("AddSandboxPolicy: failed to convert to tracing policy", logfields.Error, err)
			return fmt.Errorf("failed to convert namespaced sandboxpolicy to tracing policy: %w", err)
		}

	default:
		log.Warn("addSandboxPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return fmt.Errorf("invalid sandbox policy type: %T", obj)
	}

	log.Info("adding sandbox policy", "tp-name", tp.TpName(), "tp-info", tp.TpInfo())
	return s.AddTracingPolicy(ctx, tp)
}

func AddSandboxPolicyFromYAML(
	ctx context.Context,
	log logger.FieldLogger,
	s *sensors.Manager,
	fname string,
) error {
	fname, err := filepath.Abs(filepath.Clean(fname))
	if err != nil {
		return err
	}

	data, err := os.ReadFile(fname)
	if err != nil {
		return err
	}

	sp, err := FromYAML(string(data))
	if err != nil {
		return err
	}

	log = log.With("from-yaml", true)
	return AddSandboxPolicy(ctx, log, s, sp)
}
