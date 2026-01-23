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

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

func FromYAML(data string) ([]*v1alpha1.SmartSwitchNetworkPolicy, error) {
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(data), 4096)
	// crdctx needs the yaml as a string to parse and validate it, so we need a second yaml reader
	// to go along with the decoder as the file is parsed
	yamlReader := yaml.NewYAMLReader(bufio.NewReader(strings.NewReader(data)))
	var policies []*v1alpha1.SmartSwitchNetworkPolicy

	for {
		var unstr unstructured.Unstructured
		if err := decoder.Decode(&unstr); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to unmarshal unstructured SmartSwitch network policy YAML: %w", err)
		}
		unstrBytes, err := yamlReader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read SmartSwitch network policy YAML: %w", err)
		}

		// Skipping empty sections
		if unstr.Object == nil {
			continue
		}

		switch unstr.GetKind() {
		case v1alpha1.SNPKindDefinition:
			crdCtx, err := getSNPContext()
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve CRD context for SmartSwitchNetworkPolicy: %w", err)
			}

			snp, err := crdCtx.FromYAML(string(unstrBytes))
			if err != nil {
				return nil, err
			}

			// Validate CEL rules (x-kubernetes-validations) which are not validated by crdutils
			err = ValidateCEL(context.Background(), &unstr)
			if err != nil {
				return nil, fmt.Errorf("CEL validation failed: %w", err)
			}

			// Remove internal Kubernetes fields that should only be set by controller applied policy
			cleanK8sMetadata(&snp.ObjectMeta)
			policies = append(policies, snp)
		default:
			return nil, fmt.Errorf("invalid kind, cannot parse SmartSwitchNetworkPolicy")
		}
	}

	// Returning an error if no policies were parsed
	if len(policies) == 0 {
		return nil, fmt.Errorf("no valid policies found")
	}

	return policies, nil
}

func FromFile(path string) ([]*v1alpha1.SmartSwitchNetworkPolicy, error) {
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

func AddFromDir(dir string, policyHandler PolicyHandler) error {
	if dir == "" {
		return nil
	}

	tpMaxDepth := 1
	npFS := os.DirFS(dir)

	err := fs.WalkDir(npFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator)) >= tpMaxDepth {
				return fs.SkipDir
			}
			return nil
		}

		file := filepath.Join(dir, path)
		st, err := os.Stat(file)
		if err != nil {
			return err
		}

		if !st.Mode().IsRegular() {
			return nil
		}

		return AddFromFile(file, policyHandler)
	})

	return err
}

func AddFromYAML(data string, policyHandler PolicyHandler) error {
	policies, err := FromYAML(data)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy: %w", err)
	}
	if policies == nil {
		return fmt.Errorf("failed loading policy, policy is nil")
	}

	for _, p := range policies {
		err = Add(p, policyHandler)
		if err != nil {
			return err
		}
	}
	return nil
}

func AddFromFile(path string, policyHandler PolicyHandler) error {
	logger.GetLogger().Info("Loading policy from file", "file", path)
	policies, err := FromFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy from file %q: %w", path, err)
	}
	if policies == nil {
		return fmt.Errorf("failed loading policy from file %q, policy is nil", path)
	}

	logger.GetLogger().Info("Loading policy from file", "file", path, "policies", len(policies))
	for _, p := range policies {
		err = Add(p, policyHandler)
		if err != nil {
			return err
		}
	}
	logger.GetLogger().Info("Loading policy from file completed", "file", path, "policies", len(policies))
	return nil
}

func DeleteFromYAML(data string, policyHandler PolicyHandler) error {
	policies, err := FromYAML(data)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy: %w", err)
	}
	if policies == nil {
		return fmt.Errorf("failed loading policy, policy is nil")
	}

	for _, p := range policies {
		err = Delete(p, policyHandler)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeleteFromFile(path string, policyHandler PolicyHandler) error {
	policies, err := FromFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse SmartSwitchNetworkPolicy from file %q: %w", path, err)
	}
	if policies == nil {
		return fmt.Errorf("failed loading policy from file %q, policy is nil", path)
	}

	for _, p := range policies {
		err = Delete(p, policyHandler)
		if err != nil {
			return err
		}
	}
	return nil
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
	err = policyHandler.UpsertPolicy(resourceID, k8sRulesList, np.ResourceVersion)
	if err != nil {
		return fmt.Errorf("failed to load SmartSwitchNetworkPolicy: %w", err)
	}

	logger.GetLogger().Info("Added SmartSwitchNetworkPolicy with success", "SmartSwitchNetworkPolicy", np.Name)
	return nil
}

// Only the kind, namespace, and name of the policy need to be populated
func Delete(np *v1alpha1.SmartSwitchNetworkPolicy, policyHandler PolicyHandler) error {
	if np == nil {
		return nil
	}
	resourceID := NewResourceID(np.Kind, np.Namespace, np.Name)
	err := policyHandler.DeletePolicy(resourceID, "")
	if err != nil {
		logger.GetLogger().Error("SmartSwitchNetworkPolicy deletion failed", logfields.Error, err, "title", resourceID)
		return err
	}

	logger.GetLogger().Info("Deleted SmartSwitchNetworkPolicy with success", "SmartSwitchNetworkPolicy", np.Name)
	return nil
}

// cleanK8sMetadata removes internal Kubernetes fields from ObjectMeta
// These fields are managed by Kubernetes and should not be persisted
func cleanK8sMetadata(meta *metav1.ObjectMeta) {
	if meta == nil {
		return
	}
	// Clear internal k8s fields
	meta.ResourceVersion = ""
	meta.UID = ""
	meta.Generation = 0
	meta.CreationTimestamp = metav1.Time{}
	meta.DeletionTimestamp = nil
	meta.DeletionGracePeriodSeconds = nil
	meta.ManagedFields = nil
	meta.OwnerReferences = nil
	meta.Finalizers = nil
	// Remove kubectl last-applied-configuration annotation
	if meta.Annotations != nil {
		delete(meta.Annotations, "kubectl.kubernetes.io/last-applied-configuration")
	}
}
