package switchpolicy

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/hubble-fgs/pkg/model/server/dpu"
)

type PolicyHandler interface {
	SetL3Networks(networks *L3Networks) error
	ListPolicies() map[ResourceID]K8sRulesList
	UpsertPolicy(resourceId ResourceID, rules K8sRulesList, resourceVersion string) error
	DeletePolicy(resourceId ResourceID, resourceVersion string) error
	ResourceVersion() (string, error)
}

type DPUProgrammer interface {
	SubmitDPURuleToDPU(rule *dpu.DPUPolicyRule) error
}

type policyHandler struct {
	ctx             context.Context
	mutex           sync.RWMutex
	resourceVersion string // Latest policy object update resourceVersion from k8s, needs a read lock

	// Op counters
	upsertCounter atomic.Uint64
	deleteCounter atomic.Uint64

	dpuProgrammer DPUProgrammer
	state         *State
	repository    Repository
}

func NewPolicyHandler(ctx context.Context, dpuProgrammer DPUProgrammer) PolicyHandler {
	return &policyHandler{
		ctx:           ctx,
		dpuProgrammer: dpuProgrammer,
		state:         NewState(),
		repository:    NewRepository(),
	}
}

func (h *policyHandler) ListPolicies() map[ResourceID]K8sRulesList {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.repository.ListPolicies()
}

func (h *policyHandler) UpsertPolicy(resourceId ResourceID, rules K8sRulesList, resourceVersion string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if resourceVersion != "" {
		// Parse incoming resource version
		newVersion, err := strconv.Atoi(resourceVersion)
		if err != nil {
			logger.GetLogger().Warn("Failed to parse resource version", "resourceVersion", resourceVersion, "err", err)
			h.resourceVersion = resourceVersion
		} else if h.resourceVersion == "" {
			// No existing version, use the new one
			h.resourceVersion = resourceVersion
		} else {
			// Compare with existing version and keep the maximum
			currentVersion, err := strconv.Atoi(h.resourceVersion)
			if err != nil {
				logger.GetLogger().Warn("Failed to parse current resource version", "resourceVersion", h.resourceVersion, "err", err)
				h.resourceVersion = resourceVersion
			} else if newVersion > currentVersion {
				h.resourceVersion = resourceVersion
			}
		}
	}

	newRules, prevRules, err := h.repository.UpsertPolicy(resourceId, rules)
	if err != nil {
		return err
	}
	// First we apply new rules, then delete old ones to avoid gaps in coverage
	h.applyRules(newRules)
	h.deleteRules(prevRules)

	// Incrementing counter
	h.upsertCounter.Add(1)
	return nil
}

func (h *policyHandler) applyRules(rules K8sRulesList) {
	if rules == nil {
		return
	}

	for _, rule := range rules {
		err := h.state.AddRule(rule.ruleId, &SwitchPolicy{
			UID:    rule.uid,
			Policy: rule.SwitchPolicy,
		})
		if err != nil {
			logger.GetLogger().Error("failed to add rule to state", "rule", rule, "err", err)
		}
	}
	h.applyDelta()
}

func (h *policyHandler) DeletePolicy(resourceId ResourceID, resourceVersion string) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if resourceVersion != "" {
		h.resourceVersion = resourceVersion
	}

	deletedRules, err := h.repository.DeletePolicy(resourceId)
	if err != nil {
		return err
	}
	h.deleteRules(deletedRules)

	// Incrementing counter
	h.deleteCounter.Add(1)
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

func (h *policyHandler) ResourceVersion() (string, error) {
	h.mutex.RLock()
	resourceVersion := h.resourceVersion
	h.mutex.RUnlock()
	if resourceVersion == "" {
		return "", fmt.Errorf("latest policy is missing resource version")
	}
	return resourceVersion, nil
}

func (h *policyHandler) SetL3Networks(networks *L3Networks) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	err := h.state.SetL3Networks(networks)
	if err != nil {
		return err
	}
	h.applyDelta()
	return nil
}

func (h *policyHandler) applyDelta() {
	diffForDPU := h.state.GetDeltaToApply()
	for _, dpuRule := range diffForDPU {
		if h.ctx.Err() != nil {
			logger.GetLogger().Debug("context canceled, stopping policy deployment")
			return
		}
		err := h.dpuProgrammer.SubmitDPURuleToDPU(dpuRule)
		if err != nil {
			logger.GetLogger().Error("failed to submit rule to DPU, DPUs now out of sync", "rule", dpuRule, "err", err)
		}
	}
}
