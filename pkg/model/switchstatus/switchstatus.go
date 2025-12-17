// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchstatus

import (
	"context"
	"fmt"
	"os"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

var (
	SmartSwitchInventoryContext *crdutils.CRDContext[*v1alpha1.SmartSwitch]
)

// SmartSwitchInventory represents SmartSwitch CRD.
type SmartSwitchInventory struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta             `json:"metadata"`
	Status          v1alpha1.SmartSwitchInventory `json:"status"`
}

type DPUInventory struct {
	HardwareModel   string `json:"hardwareModel,omitempty"`
	ID              string `json:"id,omitempty"`
	ManagementIP    string `json:"managementIP,omitempty"`
	PortHigh        int    `json:"portHigh,omitempty"`
	PortLow         int    `json:"portLow,omitempty"`
	SoftwareVersion string `json:"softwareVersion,omitempty"`
}

type SmartSwitchInventoryFields struct {
	BiosVersion     string         `json:"biosVersion,omitempty"`
	DPUInventories  []DPUInventory `json:"dpuInventories,omitempty"`
	SerialNumber    string         `json:"serialNumber,omitempty"`
	ServiceIP       string         `json:"serviceIP,omitempty"`
	ServiceMAC      string         `json:"serviceMAC,omitempty"`
	SoftwareVersion string         `json:"softwareVersion,omitempty"`
}

// Name returns the name of the SmartSwitchInventory from its metadata.
func (sss *SmartSwitchInventory) Name() string {
	return sss.Metadata.Name
}

// StatusObj returns a pointer to the SmartSwitchInventory object from the v1alpha1 package.
func (sss *SmartSwitchInventory) StatusObj() *v1alpha1.SmartSwitchInventory {
	return &sss.Status
}

// GetObjectMeta returns a pointer to the ObjectMeta associated with the SmartSwitchInventory.
// This metadata typically contains information such as name, namespace, labels, and annotations.
func (sss *SmartSwitchInventory) GetObjectMeta() *metav1.ObjectMeta {
	return &sss.Metadata
}

// GetObjectMetaStruct implements crdutils.CRDObject interface.
func (sss *SmartSwitchInventory) GetObjectMetaStruct() interface{} {
	return &sss.Metadata
}

// FromYAML loads SmartSwitch from YAML.
func FromYAML(data string) (*v1alpha1.SmartSwitch, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	if unstr.GetKind() != v1alpha1.SmartSwitchKindDefinition {
		return nil, fmt.Errorf("unknown CRD kind: %s", unstr.GetKind())
	}

	crdCtx, err := getSSContext()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve CRD context for SmartSwitch: %w", err)
	}
	// FromYAML loads the SmartSwitch CRD object from the YAML string,
	// applies defaults, and validates it.
	obj, err := crdCtx.FromYAML(data)
	if err != nil {
		return nil, err
	}
	return obj, nil
}

// FromFile loads a SmartSwitch object from a YAML file.
func FromFile(path string) (*v1alpha1.SmartSwitch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(string(data))
}

// GetSmartSwitchInventory constructs, marshals, and validates a SmartSwitchInventory CR.
// Returns the validated SmartSwitch object, or an error.
func GetSmartSwitchInventory(name, namespace string, status *SmartSwitchInventoryFields) (*v1alpha1.SmartSwitch, error) {
	// Validate input parameters
	if name == "" {
		return nil, fmt.Errorf("SmartSwitch name is empty")
	}
	if namespace == "" {
		return nil, fmt.Errorf("SmartSwitch namespace is empty")
	}
	if status == nil {
		return nil, fmt.Errorf("SmartSwitch status is nil")
	}
	if status.SerialNumber == "" {
		return nil, fmt.Errorf("SmartSwitch serial number is empty")
	}

	// Convert status.DPUInventories ([]DPUInventory) to []v1alpha1.DPUInventory
	var dpuInventories []v1alpha1.DPUInventory
	for _, d := range status.DPUInventories {
		dpuInventories = append(dpuInventories, v1alpha1.DPUInventory{
			HardwareModel:   d.HardwareModel,
			ID:              d.ID,
			ManagementIP:    d.ManagementIP,
			PortHigh:        uint16(d.PortHigh),
			PortLow:         uint16(d.PortLow),
			SoftwareVersion: d.SoftwareVersion,
		})
	}

	ss := &v1alpha1.SmartSwitch{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "isovalent.com/v1alpha1",
			Kind:       v1alpha1.SmartSwitchKindDefinition,
		},
		ObjectMeta: metav1.ObjectMeta{
			// As per RFC 1123, name must be lowercase.
			Name:      strings.ToLower(name),
			Namespace: namespace,
		},
		Status: v1alpha1.SmartSwitchInventory{
			ServiceIP:       status.ServiceIP,
			ServiceMAC:      status.ServiceMAC,
			BiosVersion:     status.BiosVersion,
			SerialNumber:    status.SerialNumber,
			SoftwareVersion: status.SoftwareVersion,
			DPUInventories:  dpuInventories,
		},
	}

	// Marshal the SmartSwitch to YAML and re-parse it to apply defaults and validation.
	yamlData, err := yaml.Marshal(ss)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SmartSwitch to YAML: %w", err)
	}
	obj, err := FromYAML(string(yamlData))
	if err != nil {
		return nil, fmt.Errorf("failed to validate/default SmartSwitch: %w", err)
	}

	return obj, nil
}

// ApplySmartSwitchInventoryCR creates or updates a SmartSwitch custom resource (CR) in the Kubernetes cluster,
// and ensures its status subresource is updated with the latest information.
//
// Parameters:
//
//	ctx     - The context for the operation.
//	manager - The controller manager containing the Kubernetes client.
//	sss     - The SmartSwitch custom resource to apply.
//
// Returns:
//
//	error - An error if the operation fails, or nil if successful.
func ApplySmartSwitchInventoryCR(ctx context.Context, manager *manager.ControllerManager, sss *v1alpha1.SmartSwitch) error {
	// Check if sss is nil
	if sss == nil {
		return fmt.Errorf("SmartSwitchInventory is nil")
	}
	// Check if manager or its Manager field is nil
	if manager == nil || manager.Manager == nil {
		return fmt.Errorf("controller manager is nil")
	}
	logger.GetLogger().Debug("Applying SmartSwitchInventory CR", "name", sss.Name, "namespace", sss.Namespace)

	// Keep a copy of sss to avoid modifying the original reference
	sssCopy := sss.DeepCopy()

	// Get the client instance of the controller-runtime for CRD operations
	client := manager.Manager.GetClient()
	if client == nil {
		return fmt.Errorf("controller-runtime client is not initialized in manager")
	}

	// Create or Update the SmartSwitchInventory CR in the cluster.
	// If create fails due to already existing CR, attempt to update.
	err := client.Create(ctx, sssCopy)
	if err != nil {
		// Use apierrors.IsAlreadyExists to check for existing CR
		if !apierrors.IsAlreadyExists(err) {
			// If create fails for reasons other than already existing, return error.
			return fmt.Errorf("failed to create SmartSwitchInventory CR: %w", err)
		}

		// If create fails because resource already exists, attempt to update.
		name := sssCopy.GetName()
		namespace := sssCopy.GetNamespace()
		if name == "" {
			return fmt.Errorf("SmartSwitchInventory CR name is empty (name: '%s')", name)
		}

		// Retrieve existing CR
		existingSS := &v1alpha1.SmartSwitch{}
		err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, existingSS)
		if err != nil {
			return fmt.Errorf("failed to get SmartSwitchInventory CR: %w", err)
		}

		// Use the updated object reference for status update below.
		// Update only the status field of the existing CR with the original sss status.
		existingSS.Status = sss.Status
		sssCopy = existingSS
	} else {
		// If created successfully, update the status on the newly created object.
		sssCopy.Status = sss.Status
	}

	// Update the status subresource of the SmartSwitchInventory CR.
	err = client.Status().Update(ctx, sssCopy)
	if err != nil {
		return fmt.Errorf("failed to update SmartSwitchInventory status subresource: %w", err)
	}

	return nil
}

// DeleteSmartSwitchInventoryCR deletes a SmartSwitchInventory Custom Resource (CR) from the Kubernetes cluster.
// It takes a context, a ControllerManager, the name, and the namespace of the CR to delete.
// If the manager or its client is nil, or if the name is empty, it returns an error.
// If the CR is not found, it logs the event and returns nil.
// Otherwise, it attempts to delete the CR and logs the result.
// Returns an error if retrieval or deletion fails.
func DeleteSmartSwitchInventoryCR(ctx context.Context, manager *manager.ControllerManager, name, namespace string) error {
	if manager == nil || manager.Manager == nil {
		return fmt.Errorf("controller manager is nil")
	}
	client := manager.Manager.GetClient()
	if client == nil {
		return fmt.Errorf("controller-runtime client is not initialized in manager")
	}
	if name == "" {
		return fmt.Errorf("SmartSwitchInventory CR name is empty")
	}
	// Retrieve the existing CR to delete.
	obj := &v1alpha1.SmartSwitch{}
	err := client.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj)
	if err != nil {
		if apierrors.IsNotFound(err) {
			logger.GetLogger().Debug("SmartSwitchInventory CR not found for deletion", "name", name, "namespace", namespace)
			return nil
		}
		return fmt.Errorf("failed to get SmartSwitchInventory CR for deletion: %w", err)
	}
	// Delete the SmartSwitchInventory CR.
	err = client.Delete(ctx, obj)
	if err != nil {
		return fmt.Errorf("failed to delete SmartSwitchInventory CR: %w", err)
	}
	logger.GetLogger().Debug("SmartSwitchInventory CR deleted successfully", "name", name, "namespace", namespace)
	return nil
}
