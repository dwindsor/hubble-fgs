package library

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

type PolicyStory struct {
	Title       string
	Id          uint64
	CRDPolicy   *v1alpha1.TetragonNetworkPolicy
	CRDNSPolicy *v1alpha1.TetragonNetworkPolicyNamespaced
	IrPolicy    []*types.TetragonNetworkPolicy
}

var policyLibrary map[string]uint64
var idLibrary map[uint64]*PolicyStory
var policyId uint64

func generateId() uint64 {
	policyId++
	return policyId
}

func init() {
	policyLibrary = make(map[string]uint64)
	idLibrary = make(map[uint64]*PolicyStory)
}

func Get(name string) (*PolicyStory, bool) {
	id, ok := policyLibrary[name]
	if !ok {
		return nil, ok
	}
	p := idLibrary[id]
	return p, true
}

func Delete(name string) {
	id, ok := GetId(name)
	delete(policyLibrary, name)
	if ok {
		delete(idLibrary, id)
	}
}

func Link(title string, ref string) error {
	id, ok := GetId(title)
	if !ok {
		return fmt.Errorf("unknown link title: %s", title)
	}
	policyLibrary[ref] = id
	return nil
}

func DelLink(title string) {
	delete(policyLibrary, title)
}

func Add(p *PolicyStory) {
	_, ok := policyLibrary[p.Title]
	if ok {
		return
	}
	p.Id = generateId()
	idLibrary[p.Id] = p
	policyLibrary[p.Title] = p.Id
}

func GetId(name string) (uint64, bool) {
	id, ok := policyLibrary[name]
	if !ok {
		return uint64(0), ok
	}
	return id, true
}

func GetName(id uint64) (string, bool) {
	p, ok := idLibrary[id]
	if !ok {
		return "", ok
	}
	return p.Title, ok
}
