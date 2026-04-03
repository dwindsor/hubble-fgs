// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package nxos

import (
	"github.com/isovalent/hubble-fgs/pkg/model/switchpolicy"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
)

// Option is a functional option for configuring the NXOSManager.
type Option func(*managerOptions)

// managerOptions holds all configuration options for the manager.
type managerOptions struct {
	// Port configuration
	dpuPortLow  uint16
	dpuPortHigh uint16

	// External handlers
	dpuListener   *switchpolicy.DPUListener
	policyHandler switchpolicy.PolicyHandler

	// Mock/test options
	gnmiHandler gnmi.GnmiHandler

	// gNMI configuration for real NXOS mode
	gnmiAddress  string
	gnmiUsername string
	gnmiPassword string
	gnmiCAFile   string
	gnmiCertFile string
	gnmiKeyFile  string

	// Storage backend for persistence
	storage storage.Storage

	// Pre-seeded VRF GIDs from --vrf-map
	vrfGIDs map[string]uint16
}

// defaultOptions returns the default options.
func defaultOptions() *managerOptions {
	return &managerOptions{
		dpuPortLow:  28672,
		dpuPortHigh: 29695,
	}
}

// WithDPUPortRange sets the DPU port range.
func WithDPUPortRange(low, high uint16) Option {
	return func(o *managerOptions) {
		o.dpuPortLow = low
		o.dpuPortHigh = high
	}
}

// WithDPUListener sets the DPU listener for agent communication.
func WithDPUListener(listener *switchpolicy.DPUListener) Option {
	return func(o *managerOptions) {
		o.dpuListener = listener
	}
}

// WithPolicyHandler sets the policy handler for policy processing.
func WithPolicyHandler(handler switchpolicy.PolicyHandler) Option {
	return func(o *managerOptions) {
		o.policyHandler = handler
	}
}

// WithMockGnmiHandler sets a mock gNMI handler for testing or when NXOS is disabled.
// If handler is nil, a new mock handler is created.
func WithMockGnmiHandler(handler gnmi.GnmiHandler) Option {
	return func(o *managerOptions) {
		if handler != nil {
			o.gnmiHandler = handler
		} else {
			o.gnmiHandler = mock.NewHandler()
		}
	}
}

// WithStorage sets a custom storage backend.
// Use storage.NewMemoryStorage() for testing or storage.NewFileStorage() for production.
func WithStorage(s storage.Storage) Option {
	return func(o *managerOptions) {
		o.storage = s
	}
}

// WithVRFGIDs sets the pre-seeded GID map for the VRF store. Entries come from
// the parsed --vrf-map flag so the store honors operator-assigned GIDs instead
// of allocating them sequentially.
func WithVRFGIDs(seeds map[string]uint16) Option {
	return func(o *managerOptions) {
		o.vrfGIDs = seeds
	}
}

// WithGnmiAddress sets the gNMI target address (host:port).
func WithGnmiAddress(addr string) Option {
	return func(o *managerOptions) {
		o.gnmiAddress = addr
	}
}

// WithGnmiCredentials sets the gNMI username and password.
func WithGnmiCredentials(username, password string) Option {
	return func(o *managerOptions) {
		o.gnmiUsername = username
		o.gnmiPassword = password
	}
}

// WithGnmiTLS sets the TLS configuration for gNMI.
func WithGnmiTLS(caFile, certFile, keyFile string) Option {
	return func(o *managerOptions) {
		o.gnmiCAFile = caFile
		o.gnmiCertFile = certFile
		o.gnmiKeyFile = keyFile
	}
}
