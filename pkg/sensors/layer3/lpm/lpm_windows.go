// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package lpm

import (
	"errors"
	"net/netip"

	"github.com/cilium/tetragon/pkg/bpf"
)

func NewLPM() (LPMMap, error) {
	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		return nil, errors.New("tcp preload collection is nil")
	}
	addr4lpm := coll.Maps[Addr4lpmMapName]
	if addr4lpm == nil {
		return nil, errors.New("failed to load addr4 LPM Map from collection")
	}
	addr6lpm := coll.Maps[Addr6lpmMapName]
	if err != nil {
		return nil, errors.New("failed to load addr6 LPM Map from collection")
	}

	return &lpmMapImpl{
		lpmBackend: &ebpfBackend{
			addr6: addr6lpm,
			addr4: addr4lpm,
		},
		refCount: map[netip.Prefix]int{},
	}, nil
}
