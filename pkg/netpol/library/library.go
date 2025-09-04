package library

import (
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

type PolicyStory struct {
	Title       string
	Id          uint64
	Rules       map[string]uint64
	CRDPolicy   *v1alpha1.TetragonNetworkPolicy
	CRDNSPolicy *v1alpha1.TetragonNetworkPolicyNamespaced
	IrPolicy    []*types.TetragonNetworkPolicy
}

type policyRepositoryImpl struct {
	policyLibrary map[string]uint64
	idLibrary     map[uint64]*PolicyStory
	policyId      uint64
	ruleId        uint64
}

type PolicyRepository interface {
	Get(name string) (*PolicyStory, bool)
	Delete(name string)
	Link(title string, ref string) error
	DelLink(title string)
	AddRule(p *PolicyStory, rule string)
	Add(p *PolicyStory)
	GetId(name string) (uint64, bool)
	GetRuleId(policy, rule string) (uint64, bool)
	GetName(id uint64) (string, bool)
	GetRule(policy string, id uint64, deny, allow bool) (string, bool)
	GetList() []string
}

type PolicyRepositoryIDReader interface {
	GetId(name string) (uint64, bool)
	GetRuleId(policy, rule string) (uint64, bool)
}

var (
	repo            *policyRepositoryImpl
	initGlobalCache sync.Once
)

func GetRepository() PolicyRepository {
	initGlobalCache.Do(func() {
		repo = &policyRepositoryImpl{}
		repo.policyLibrary = make(map[string]uint64)
		repo.idLibrary = make(map[uint64]*PolicyStory)
	})
	return repo
}

func (r *policyRepositoryImpl) generateId() uint64 {
	r.policyId++
	return r.policyId
}

func (r *policyRepositoryImpl) generateRuleId() uint64 {
	r.ruleId++
	return r.ruleId
}

func (r *policyRepositoryImpl) Get(name string) (*PolicyStory, bool) {
	id, ok := r.policyLibrary[name]
	if !ok {
		return nil, ok
	}
	p := r.idLibrary[id]
	return p, true
}

func (r *policyRepositoryImpl) Delete(name string) {
	id, ok := r.GetId(name)
	delete(r.policyLibrary, name)
	if ok {
		delete(r.idLibrary, id)
	}
	for str, n := range r.policyLibrary {
		if n == id {
			r.DelLink(str)
		}
	}
}

func (r *policyRepositoryImpl) Link(title string, ref string) error {
	id, ok := r.GetId(title)
	if !ok {
		return fmt.Errorf("unknown link title: %s", title)
	}
	r.policyLibrary[ref] = id
	return nil
}

func (r *policyRepositoryImpl) DelLink(title string) {
	delete(r.policyLibrary, title)
}

func (r *policyRepositoryImpl) AddRule(p *PolicyStory, rule string) {
	if _, ok := p.Rules[rule]; ok {
		return
	}
	ruleID := r.generateRuleId()
	p.Rules[rule] = ruleID
}

func (r *policyRepositoryImpl) Add(p *PolicyStory) {
	_, ok := r.policyLibrary[p.Title]
	if ok {
		return
	}
	p.Id = r.generateId()
	r.idLibrary[p.Id] = p
	r.policyLibrary[p.Title] = p.Id
}

func (r *policyRepositoryImpl) GetId(name string) (uint64, bool) {
	id, ok := r.policyLibrary[name]
	if !ok {
		return uint64(0), ok
	}
	return id, true
}

func (r *policyRepositoryImpl) GetRuleId(policy, rule string) (uint64, bool) {
	p, ok := r.Get(policy)
	if !ok {
		return uint64(0), ok
	}
	id, ok := p.Rules[rule]
	if !ok {
		return uint64(0), ok
	}
	return id, true
}

func (r *policyRepositoryImpl) GetName(id uint64) (string, bool) {
	p, ok := r.idLibrary[id]
	if !ok {
		return "", ok
	}
	return p.Title, ok
}

func (r *policyRepositoryImpl) GetRule(policy string, id uint64, deny, allow bool) (string, bool) {
	p, ok := r.Get(policy)
	if !ok {
		return "", false
	}

	// ID == 0 special case as the default rule.
	if id == uint64(0) {
		if allow {
			return "tetragon:default-allow", true
		} else if deny {
			return "tetragon:default-deny", true
		}
		return "", true
	}

	for k, v := range p.Rules {
		if v == id {
			return k, true
		}
	}
	return "", false
}

func (r *policyRepositoryImpl) GetList() []string {
	names := []string{}
	for _, story := range r.idLibrary {
		names = append(names, story.Title)
	}
	return names
}
