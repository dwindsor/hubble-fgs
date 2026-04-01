// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows && !nok8s

package server

import (
	"github.com/cilium/tetragon/pkg/cgidmap"
	lru "github.com/hashicorp/golang-lru/v2"
)

var cgmap cgidmap.Map

func initContainerIDMap() error {
	var err error
	cgmap, err = cgidmap.GlobalMap()
	if cgmap == nil || err != nil {
		return err
	}

	return nil
}

func getContainerID(cgroupid uint64, deletedContainerIdCache *lru.Cache[uint64, string]) (string, bool) {
	cid, ok := deletedContainerIdCache.Get(cgroupid)
	if !ok {
		cid, ok = cgmap.Get(cgroupid)
		if ok {
			deletedContainerIdCache.Add(cgroupid, cid)
		}
	}

	return cid, ok
}
