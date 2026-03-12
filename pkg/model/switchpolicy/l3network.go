// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import "fmt"

type VrfName string
type VrfGID uint32

type L3Networks struct {
	byName map[VrfName]VrfGID
	byGID  map[VrfGID]VrfName
}

// All L3Networks are initialized with an empty string vrf name (no vrf) mapped to
// the vrf id value of 0.  This ensures that rules with no vrf are always applied.
func NewL3Networks() *L3Networks {
	return &L3Networks{
		byName: map[VrfName]VrfGID{
			"": 0,
		},
		byGID: map[VrfGID]VrfName{
			0: "",
		},
	}
}

// Duplicate vrf names or ids will fail to be added, so they must be removed first.
func (l3 *L3Networks) Add(name VrfName, gid VrfGID) error {
	if _, ok := l3.byName[name]; ok {
		return fmt.Errorf("L3 network with name %s already exists", name)
	}
	if k, ok := l3.byGID[gid]; ok {
		return fmt.Errorf("L3 network VRF %s with GID %d already exists", k, gid)
	}
	l3.byName[name] = gid
	l3.byGID[gid] = name
	return nil
}

func (l3 *L3Networks) Remove(name VrfName) error {
	if gid, ok := l3.byName[name]; ok {
		delete(l3.byName, name)
		delete(l3.byGID, gid)
		return nil
	}
	return fmt.Errorf("L3 network with name %s does not exist", name)
}

// HasVRF returns true if the VRF name exists in the L3Networks
func (l3 *L3Networks) HasVRF(name VrfName) bool {
	_, ok := l3.byName[name]
	return ok
}

// GIDChange records an in-place VRF GID update.
type GIDChange struct {
	OldGID VrfGID
	NewGID VrfGID
}

// Diff computes the changes needed to transition from the current state to incoming.
// added: VRFs in incoming but not in current.
// removed: VRFs in current but not in incoming.
// changed: VRFs in both with different GIDs.
func (l3 *L3Networks) Diff(incoming *L3Networks) (
	added map[VrfName]VrfGID,
	removed map[VrfName]VrfGID,
	changed map[VrfName]GIDChange,
) {
	added = make(map[VrfName]VrfGID)
	removed = make(map[VrfName]VrfGID)
	changed = make(map[VrfName]GIDChange)

	for name, inGID := range incoming.byName {
		if curGID, ok := l3.byName[name]; ok {
			if curGID != inGID {
				changed[name] = GIDChange{OldGID: curGID, NewGID: inGID}
			}
		} else {
			added[name] = inGID
		}
	}
	for name, curGID := range l3.byName {
		if _, ok := incoming.byName[name]; !ok {
			removed[name] = curGID
		}
	}
	return added, removed, changed
}

// Copy creates a deep copy of the L3Networks
func (l3 *L3Networks) Copy() *L3Networks {
	l3Copy := &L3Networks{
		byName: make(map[VrfName]VrfGID, len(l3.byName)),
		byGID:  make(map[VrfGID]VrfName, len(l3.byGID)),
	}
	for name, gid := range l3.byName {
		l3Copy.byName[name] = gid
	}
	for gid, name := range l3.byGID {
		l3Copy.byGID[gid] = name
	}
	return l3Copy
}
