//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apischema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	structuraldefaulting "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/defaulting"
	structurallisttype "k8s.io/apiextensions-apiserver/pkg/apiserver/schema/listtype"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	apivalidation "k8s.io/apimachinery/pkg/api/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kube-openapi/pkg/validation/validate"
	"sigs.k8s.io/yaml"
)

var getStructuralSandboxPolicy func() (*apischema.Structural, error) = sync.OnceValues(
	func() (*apischema.Structural, error) {
		var crdSandboxPol ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&client.SandboxPolicyCRD.Definition,
			&crdSandboxPol,
			nil,
		)
		if err != nil {
			return nil, err
		}
		return apischema.NewStructural(crdSandboxPol.Spec.Validation.OpenAPIV3Schema)
	},
)

type validatorInfo struct {
	validator        validation.SchemaValidator
	structuralSchema *apischema.Structural
}

type validatorMap = map[schema.GroupVersionKind]validatorInfo

var getValidators func() (validatorMap, error) = sync.OnceValues(
	func() (validatorMap, error) {

		ret := make(validatorMap)

		crd := &client.SandboxPolicyCRD.Definition
		internal := &ext.CustomResourceDefinition{}
		if err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(crd, internal, nil); err != nil {
			return nil, err
		}

		for _, ver := range crd.Spec.Versions {

			bytes, err := json.Marshal(ver.Schema)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal schema: %w", err)
			}

			var crv extv1.CustomResourceValidation
			err = json.Unmarshal(bytes, &crv)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshall CRD: %w", err)
			}

			var crvInternal ext.CustomResourceValidation
			err = extv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
				&crv,
				&crvInternal,
				nil,
			)
			if err != nil {
				return nil, fmt.Errorf("coversion failed: %w", err)
			}

			validator, _, err := validation.NewSchemaValidator(crvInternal.OpenAPIV3Schema)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize validator: %w", err)
			}

			key := schema.GroupVersionKind{
				Version: ver.Name,
				Group:   crd.Spec.Group,
				Kind:    crd.Spec.Names.Kind,
			}

			structural, err := apischema.NewStructural(crvInternal.OpenAPIV3Schema)
			if err != nil {
				return nil, err
			}

			ret[key] = validatorInfo{
				validator:        validator,
				structuralSchema: structural,
			}

		}

		return ret, nil
	},
)

func validatePolicy(
	unstructuredPolicy unstructured.Unstructured,
	p *v1alpha1.SandboxPolicy,
) (*validate.Result, field.ErrorList, error) {
	// first, validate meta
	// SandboxPolicy is namespaced
	var metaErrors []error
	errorList := apivalidation.ValidateObjectMeta(
		&p.ObjectMeta,
		true, /* SanbdoxPolicy is namespaced */
		apivalidation.NameIsDNSSubdomain,
		field.NewPath("metadata"))
	for _, err := range errorList {
		metaErrors = append(metaErrors, err)
	}

	// then, validate spec
	validatorMap, err := getValidators()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize validators: %w", err)
	}

	v, ok := validatorMap[p.GroupVersionKind()]
	if !ok {
		return nil, nil, fmt.Errorf("could not find validator for: " + p.GroupVersionKind().String())
	}

	specErrors := v.validator.Validate(p)
	// combine meta and spec validation errors
	specErrors.Errors = append(metaErrors, specErrors.Errors...)

	listErrs := structurallisttype.ValidateListSetsAndMaps(nil, v.structuralSchema, unstructuredPolicy.Object)
	return specErrors, listErrs, nil
}

func FromYAML(data string) (*v1alpha1.SandboxPolicy, error) {
	rawPolicy, unstructuredPolicy, err := applyDefaults([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("error applying CRD defaults: %w", err)
	}

	var policy v1alpha1.SandboxPolicy
	err = yaml.UnmarshalStrict(rawPolicy, &policy)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
	}

	validationResult, listErrs, err := validatePolicy(unstructuredPolicy, &policy)
	if err != nil {
		return nil, err
	}

	if len(validationResult.Errors) > 0 {
		err = errors.Join(err, validationResult.AsError())
	}
	if len(listErrs) > 0 {
		err = errors.Join(err, listErrs.ToAggregate())
	}

	if err != nil {
		return nil, fmt.Errorf("vailidation failed: %w", err)
	}

	return &policy, nil
}

func applyDefaults(rawPolicy []byte) ([]byte, unstructured.Unstructured, error) {

	var policyUnstr unstructured.Unstructured

	schemaSP, err := getStructuralSandboxPolicy()
	if err != nil {
		return nil, policyUnstr, err
	}

	err = yaml.UnmarshalStrict(rawPolicy, &policyUnstr)
	if err != nil {
		return nil, policyUnstr, fmt.Errorf("failed to unmarshall policy: %v", err)
	}

	kind := policyUnstr.GetKind()
	switch kind {
	case "SandboxPolicy":
		structuraldefaulting.Default(policyUnstr.Object, schemaSP)
	default:
		return nil, policyUnstr, fmt.Errorf("unknown kind: %s", kind)
	}

	pol, err := policyUnstr.MarshalJSON()
	return pol, policyUnstr, err
}
