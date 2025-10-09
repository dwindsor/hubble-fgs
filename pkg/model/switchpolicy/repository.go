package switchpolicy

import "fmt"

type ResourceID struct {
	kind      string
	namespace string
	name      string
}

func NewResourceID(kind, namespace, name string) ResourceID {
	return ResourceID{
		kind:      kind,
		namespace: namespace,
		name:      name,
	}
}

// ID for internal tracking of rules
type ruleID uint32

// Human readable unique identifier
type UniqueID struct {
	PolicyName string
	RuleName   string
}

type PolicyRule struct {
	ruleName     string
	switchPolicy *SmartSwitchNetworkPolicy

	// Internal fields for repository to track rules
	ruleId ruleID
	uid    UniqueID
}

func NewPolicyRule(ruleName string, switchPolicy *SmartSwitchNetworkPolicy) *PolicyRule {
	return &PolicyRule{
		ruleName:     ruleName,
		switchPolicy: switchPolicy,
	}
}

type K8sRulesList []*PolicyRule

type Repository interface {
	UpsertPolicy(resourceId ResourceID, rules K8sRulesList) (newRules, previousPolicy K8sRulesList, err error)
	DeletePolicy(resourceId ResourceID) (deletedPolicy K8sRulesList, err error)
}

type repository struct {
	policyByResourceID map[ResourceID]K8sRulesList

	nextRuleId ruleID
}

func NewRepository() Repository {
	return &repository{
		policyByResourceID: make(map[ResourceID]K8sRulesList),
	}
}

func (r *repository) UpsertPolicy(resourceId ResourceID, rules K8sRulesList) (newRules, previousPolicy K8sRulesList, err error) {
	if existingPolicy, ok := r.policyByResourceID[resourceId]; ok {
		previousPolicy = existingPolicy
	}
	for _, rule := range rules {
		r.nextRuleId++
		rule.ruleId = r.nextRuleId

		rule.uid = UniqueID{
			PolicyName: fmt.Sprintf("%s/%s/%s", resourceId.kind, resourceId.namespace, resourceId.name),
			RuleName:   fmt.Sprintf("%s/%d", rule.ruleName, rule.ruleId),
		}
	}

	r.policyByResourceID[resourceId] = rules
	return rules, previousPolicy, nil
}

func (r *repository) DeletePolicy(resourceID ResourceID) (deletedPolicy K8sRulesList, err error) {
	if policy, ok := r.policyByResourceID[resourceID]; ok {
		delete(r.policyByResourceID, resourceID)
		return policy, nil
	}
	return nil, fmt.Errorf("policy with resource ID %s not found", resourceID)
}
