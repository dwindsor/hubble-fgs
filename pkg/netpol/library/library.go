package library

import (
	"fmt"
	"sync"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/isovalent/ipa/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

type datapathRuleID uint64
type datapathPolicyID uint64

type PolicyStory struct {
	Title string

	CRDPolicy   *v1alpha1.TetragonNetworkPolicy
	CRDNSPolicy *v1alpha1.TetragonNetworkPolicyNamespaced
	IrPolicy    []*types.TetragonNetworkPolicy

	// Internal fields for repository use only
	rules map[types.TetragonPolicyUniqueID]datapathRuleID
	id    datapathPolicyID
}

type policyRepositoryImpl struct {
	policyLibrary map[string]datapathPolicyID
	idLibrary     map[datapathPolicyID]*PolicyStory
	policyId      datapathPolicyID
	ruleId        datapathRuleID
}

type PolicyRepository interface {
	Get(name string) *PolicyStory
	Delete(name string)
	Add(p *PolicyStory)
	GetId(name string) (uint64, bool)
	GetRuleId(ruleId types.TetragonPolicyUniqueID) (uint64, bool)
	GetName(id uint64) (string, bool)
	GetRule(policy string, id uint64, deny, allow bool) (string, bool)
	GetList() []string
}

type PolicyRepositoryIDReader interface {
	GetId(name string) (uint64, bool)
	GetRuleId(ruleId types.TetragonPolicyUniqueID) (uint64, bool)
}

var (
	repo            *policyRepositoryImpl
	initGlobalCache sync.Once
)

func GetRepository() PolicyRepository {
	initGlobalCache.Do(func() {
		repo = &policyRepositoryImpl{}
		repo.policyLibrary = make(map[string]datapathPolicyID)
		repo.idLibrary = make(map[datapathPolicyID]*PolicyStory)
	})
	return repo
}

func (r *policyRepositoryImpl) generateId() datapathPolicyID {
	r.policyId++
	return r.policyId
}

func (r *policyRepositoryImpl) generateRuleId() datapathRuleID {
	r.ruleId++
	return r.ruleId
}

func (r *policyRepositoryImpl) Get(name string) *PolicyStory {
	id, ok := r.policyLibrary[name]
	if !ok {
		return nil
	}
	return r.idLibrary[id]
}

func (r *policyRepositoryImpl) Delete(name string) {
	id := r.policyLibrary[name]
	delete(r.policyLibrary, name)
	delete(r.idLibrary, id)
}

func (r *policyRepositoryImpl) Add(p *PolicyStory) {
	_, ok := r.policyLibrary[p.Title]
	if !ok {
		p.id = r.generateId()
		r.idLibrary[p.id] = p
		r.policyLibrary[p.Title] = p.id
	}
	p.rules = make(map[types.TetragonPolicyUniqueID]datapathRuleID)
	uniqueDescriptions := set.Set[string]{}
	for _, policy := range p.IrPolicy {
		ruleID := r.generateRuleId()
		policy.PolicyUID.PolicyName = p.Title

		if uniqueDescriptions.Has(policy.RuleDescription) {
			// This means we have a conflicting rule descriptions
			policy.PolicyUID.RuleName = fmt.Sprintf("%s#%d", policy.PolicyUID.RuleName, ruleID)
		} else {
			policy.PolicyUID.RuleName = policy.RuleDescription
		}
		uniqueDescriptions.Insert(policy.PolicyUID.RuleName)

		p.rules[policy.PolicyUID] = ruleID
	}
}

func (r *policyRepositoryImpl) GetId(name string) (uint64, bool) {
	id, ok := r.policyLibrary[name]
	if !ok {
		return uint64(0), ok
	}
	return uint64(id), true
}

func (r *policyRepositoryImpl) GetRuleId(ruleId types.TetragonPolicyUniqueID) (uint64, bool) {
	p := r.Get(ruleId.PolicyName)
	if p == nil {
		return uint64(0), false
	}
	id, ok := p.rules[ruleId]
	if !ok {
		return uint64(0), false
	}
	return uint64(id), true
}

func (r *policyRepositoryImpl) GetName(id uint64) (string, bool) {
	p, ok := r.idLibrary[datapathPolicyID(id)]
	if !ok {
		return "", ok
	}
	return p.Title, ok
}

func (r *policyRepositoryImpl) GetRule(policy string, id uint64, deny, allow bool) (string, bool) {
	p := r.Get(policy)
	if p == nil {
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

	for k, v := range p.rules {
		if v == datapathRuleID(id) {
			return k.RuleName, true
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
