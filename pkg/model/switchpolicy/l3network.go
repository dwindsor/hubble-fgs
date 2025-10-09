package switchpolicy

import "fmt"

type VrfName string
type VrfGID uint32

type L3Networks struct {
	byName map[VrfName]VrfGID
	byGID  map[VrfGID]VrfName
}

func NewL3Networks() *L3Networks {
	return &L3Networks{
		byName: make(map[VrfName]VrfGID),
		byGID:  make(map[VrfGID]VrfName),
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
