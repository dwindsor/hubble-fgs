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

func (l3 *L3Networks) Add(name VrfName, gid VrfGID) error {
	if _, ok := l3.byName[name]; ok {
		return fmt.Errorf("L3 network with name %s already exists", name)
	}
	if _, ok := l3.byGID[gid]; ok {
		return fmt.Errorf("L3 network with GID %d already exists", gid)
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
