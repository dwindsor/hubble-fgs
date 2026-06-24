// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux && !nok8s

package tetragon

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/manager/events"
	"github.com/cilium/tetragon/pkg/option"

	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
)

// enableHostPodHandlers wires the host-specific (Linux-only) pod-event
// consumers into the supplied source: cgidmap (when enabled) and the file
// sensor's FIM pod tracking. Both previously relied on the upstream podhooks
// auto-install (removed upstream), so they are now registered explicitly.
//
// NB: this file is gated on `linux` rather than OSS's `!windows` (cgidmap
// alone) because the file sensor (pkg/sensors/file) is Linux-only. Keep the
// build tag aligned with pkg/sensors/file so the file import stays valid.
func enableHostPodHandlers(src events.PodEventSource) error {
	if option.Config.EnableCgIDmap {
		if err := cgidmap.Register(src); err != nil {
			return fmt.Errorf("failed to register cgidmap pod handlers: %w", err)
		}
	}
	if err := file.RegisterPodHandlers(src); err != nil {
		return fmt.Errorf("failed to register file sensor pod handlers: %w", err)
	}
	return nil
}
