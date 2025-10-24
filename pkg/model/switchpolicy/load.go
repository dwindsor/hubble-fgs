package switchpolicy

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

func FromYAML(data string) (*v1alpha1.SmartSwitchNetworkPolicy, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal unstructured SmartSwitch network policy YAML: %w", err)
	}

	switch unstr.GetKind() {
	case v1alpha1.SNPKindDefinition:
		crdCtx, err := getSNPContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for SmartSwitchNetworkPolicy: %w", err)
		}

		snp, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return snp, nil
	default:
		return nil, nil
	}
}

func FromFile(path string) (*v1alpha1.SmartSwitchNetworkPolicy, error) {
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, err
	}

	return FromYAML(string(data))
}

func AddFromYAML(data string, policyHandler PolicyHandler) error {
	policy, err := FromYAML(data)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("failed loading policy, policy is nil")
	}

	return Add(policy, policyHandler)
}

func AddFromFile(path string, policyHandler PolicyHandler) error {
	policy, err := FromFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy from file %q: %w", path, err)
	}
	if policy == nil {
		return fmt.Errorf("failed loading policy from file %q, policy is nil", path)
	}

	return Add(policy, policyHandler)
}

func DeleteFromYAML(data string, policyHandler PolicyHandler) error {
	policy, err := FromYAML(data)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy: %w", err)
	}
	if policy == nil {
		return fmt.Errorf("failed loading policy, policy is nil")
	}

	return Delete(policy, policyHandler)
}

func DeleteFromFile(path string, policyHandler PolicyHandler) error {
	policy, err := FromFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy from file %q: %w", path, err)
	}
	if policy == nil {
		return fmt.Errorf("failed loading policy from file %q, policy is nil", path)
	}

	return Delete(policy, policyHandler)
}

func Add(np *v1alpha1.SmartSwitchNetworkPolicy, policyHandler PolicyHandler) error {
	policies, err := ToSmartSwitchNetworkPolicies(np)
	if err != nil {
		return fmt.Errorf("failed to convert SmartSwitchNetworkPolicy %s to internal representation: %w", np.Name, err)
	}
	if np == nil {
		return nil
	}

	resourceID := NewResourceID(np.Kind, np.Namespace, np.Name)
	var k8sRulesList K8sRulesList
	for _, pol := range policies {
		hash, err := pol.Hash()
		if err != nil {
			logger.GetLogger().Error("failed to calculate policy checksum, corrupted policy rule", logfields.Error, err, "title", resourceID, "policy rule", *pol)
			continue
		}
		k8sRulesList = append(k8sRulesList, NewPolicyRule(hex.EncodeToString(hash[:]), pol))
	}
	err = policyHandler.UpsertPolicy(resourceID, k8sRulesList)
	if err != nil {
		return fmt.Errorf("failed to load SmartSwitchNetworkPolicy: %w", err)
	}

	logger.GetLogger().Info("Added SmartSwitchNetworkPolicy with success", "SmartSwitchNetworkPolicy", np.Name)
	return nil
}

func Delete(np *v1alpha1.SmartSwitchNetworkPolicy, policyHandler PolicyHandler) error {
	if np == nil {
		return nil
	}
	resourceID := NewResourceID(np.Kind, np.Namespace, np.Name)
	err := policyHandler.DeletePolicy(resourceID)
	if err != nil {
		logger.GetLogger().Warn("SmartSwitchNetworkPolicy deletion failed", logfields.Error, err, "title", resourceID)
		return err
	}
	return nil
}
