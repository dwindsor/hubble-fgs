package switchpolicy

import (
	"sync"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

type PolicyHandler interface {
	SetL3Networks(networks *L3Networks) error
	UpsertPolicy(resourceId ResourceID, rules K8sRulesList) error
	DeletePolicy(resourceId ResourceID) error
}

type DPUProgrammer interface {
	SubmitDPURuleToDPU(rule *dpu.DPUPolicyRule) error
}

type policyHandler struct {
	mutex sync.Mutex

	dpuProgrammer DPUProgrammer
	state         *State
	repository    Repository
}

func NewPolicyHandler(dpuProgrammer DPUProgrammer) PolicyHandler {
	return &policyHandler{
		dpuProgrammer: dpuProgrammer,
		state:         NewState(),
		repository:    NewRepository(),
	}
}

func (h *policyHandler) UpsertPolicy(resourceId ResourceID, rules K8sRulesList) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	newRules, prevRules, err := h.repository.UpsertPolicy(resourceId, rules)
	if err != nil {
		return err
	}
	// First we apply new rules, then delete old ones to avoid gaps in coverage
	h.applyRules(newRules)
	h.deleteRules(prevRules)
	return nil
}

func (h *policyHandler) applyRules(rules K8sRulesList) {
	if rules == nil {
		return
	}

	for _, rule := range rules {
		err := h.state.AddRule(rule.ruleId, &SwitchPolicy{
			UID:    rule.uid,
			Policy: rule.switchPolicy,
		})
		if err != nil {
			logger.GetLogger().Error("failed to add rule to state", "rule", rule, "err", err)
		}
	}
	h.applyDelta()
}

func (h *policyHandler) DeletePolicy(resourceId ResourceID) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	deletedRules, err := h.repository.DeletePolicy(resourceId)
	if err != nil {
		return err
	}
	h.deleteRules(deletedRules)
	return nil
}

func (h *policyHandler) deleteRules(rules K8sRulesList) {
	if rules == nil {
		return
	}
	for _, rule := range rules {
		h.state.RemoveRuleByID(rule.ruleId)
	}
	h.applyDelta()
}

func (h *policyHandler) SetL3Networks(networks *L3Networks) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.state.SetL3Networks(networks)
	h.applyDelta()
	return nil
}

func (h *policyHandler) applyDelta() {
	diffForDPU := h.state.GetDeltaToApply()
	for _, dpuRule := range diffForDPU {
		err := h.dpuProgrammer.SubmitDPURuleToDPU(dpuRule)
		if err != nil {
			logger.GetLogger().Error("failed to submit rule to DPU, DPUs now out of sync", "rule", dpuRule, "err", err)
		}
	}
}
