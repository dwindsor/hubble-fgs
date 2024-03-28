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

var getStructuralSandboxPolicyNamespaced func() (*apischema.Structural, error) = sync.OnceValues(
	func() (*apischema.Structural, error) {
		var crdSandboxPol ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(
			&client.SandboxPolicyNamespacedCRD.Definition,
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

		crds := []*extv1.CustomResourceDefinition{
			&client.SandboxPolicyCRD.Definition,
			&client.SandboxPolicyNamespacedCRD.Definition,
		}

		for _, crd := range crds {
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
		}

		return ret, nil
	},
)

func validatePolicy(
	unstructuredPolicy unstructured.Unstructured,
	policy interface{},
) (*validate.Result, field.ErrorList, error) {

	var metaErrors []error
	var errorList field.ErrorList
	var kind schema.GroupVersionKind
	switch pol := policy.(type) {
	case *v1alpha1.SandboxPolicy:
		// first, validate meta
		errorList = apivalidation.ValidateObjectMeta(
			&pol.ObjectMeta,
			false, /* SanbdoxPolicy is not namespaced */
			apivalidation.NameIsDNSSubdomain,
			field.NewPath("metadata"))
		kind = pol.GroupVersionKind()
	case *v1alpha1.SandboxPolicyNamespaced:
		// first, validate meta
		errorList = apivalidation.ValidateObjectMeta(
			&pol.ObjectMeta,
			true, /* SanbdoxPolicyNamespaced is namespaced */
			apivalidation.NameIsDNSSubdomain,
			field.NewPath("metadata"))
		kind = pol.GroupVersionKind()
	default:
		return nil, nil, fmt.Errorf("unexpected policy type: %T", policy)
	}

	for _, err := range errorList {
		metaErrors = append(metaErrors, err)
	}

	// then, validate spec
	validatorMap, err := getValidators()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize validators: %w", err)
	}

	v, ok := validatorMap[kind]
	if !ok {
		return nil, nil, fmt.Errorf("could not find validator for: " + kind.String())
	}

	specErrors := v.validator.Validate(policy)
	// combine meta and spec validation errors
	specErrors.Errors = append(metaErrors, specErrors.Errors...)

	listErrs := structurallisttype.ValidateListSetsAndMaps(nil, v.structuralSchema, unstructuredPolicy.Object)
	return specErrors, listErrs, nil
}

func FromYAML(data string) (*v1alpha1.SandboxPolicy, *v1alpha1.SandboxPolicyNamespaced, error) {
	rawPolicy, unstructuredPolicy, err := applyDefaults([]byte(data))
	if err != nil {
		return nil, nil, fmt.Errorf("error applying CRD defaults: %w", err)
	}

	var policyCW *v1alpha1.SandboxPolicy
	var policyNS *v1alpha1.SandboxPolicyNamespaced
	var policy interface{}

	kind := unstructuredPolicy.GetKind()
	switch kind {
	case "SandboxPolicy":
		var polCW v1alpha1.SandboxPolicy
		err = yaml.UnmarshalStrict(rawPolicy, &polCW)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
		}
		policyCW = &polCW
		policy = policyCW
	case "SandboxPolicyNamespaced":
		var polNS v1alpha1.SandboxPolicyNamespaced
		err = yaml.UnmarshalStrict(rawPolicy, &polNS)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal object with defaults: %w", err)
		}
		policyNS = &polNS
		policy = policyNS
	default:
		return nil, nil, fmt.Errorf("unknown kind: %s", kind)
	}

	validationResult, listErrs, err := validatePolicy(unstructuredPolicy, policy)
	if err != nil {
		return nil, nil, err
	}

	if len(validationResult.Errors) > 0 {
		err = errors.Join(err, validationResult.AsError())
	}
	if len(listErrs) > 0 {
		err = errors.Join(err, listErrs.ToAggregate())
	}

	if err != nil {
		return nil, nil, fmt.Errorf("vailidation failed: %w", err)
	}

	return policyCW, policyNS, nil
}

func applyDefaults(rawPolicy []byte) ([]byte, unstructured.Unstructured, error) {

	var policyUnstr unstructured.Unstructured
	err := yaml.UnmarshalStrict(rawPolicy, &policyUnstr)
	if err != nil {
		return nil, policyUnstr, fmt.Errorf("failed to unmarshall policy: %v", err)
	}

	kind := policyUnstr.GetKind()
	var schema *apischema.Structural
	switch kind {
	case "SandboxPolicy":
		schema, err = getStructuralSandboxPolicy()
		if err != nil {
			return nil, policyUnstr, err
		}
		structuraldefaulting.Default(policyUnstr.Object, schema)

	case "SandboxPolicyNamespaced":
		schema, err := getStructuralSandboxPolicyNamespaced()
		if err != nil {
			return nil, policyUnstr, err
		}
		structuraldefaulting.Default(policyUnstr.Object, schema)

	default:
		return nil, policyUnstr, fmt.Errorf("unknown kind: %s", kind)
	}

	pol, err := policyUnstr.MarshalJSON()
	return pol, policyUnstr, err
}
