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
	"context"
	"errors"
	"fmt"
	"sync"

	ext "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apischema "k8s.io/apiextensions-apiserver/pkg/apiserver/schema"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation/field"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
)

var (
	celValidator     *cel.Validator
	celValidatorOnce sync.Once
	celValidatorErr  error
	structuralSchema *apischema.Structural
)

// initCELValidator initializes the CEL validator from the CRD definition.
// This is called once lazily when validation is first needed.
func initCELValidator() error {
	celValidatorOnce.Do(func() {
		var internal ext.CustomResourceDefinition
		err := extv1.Convert_v1_CustomResourceDefinition_To_apiextensions_CustomResourceDefinition(&SmartSwitchNetworkPolicyCRD.Definition, &internal, nil)
		if err != nil {
			celValidatorErr = fmt.Errorf("failed to convert CRD: %w", err)
			return
		}

		structural, err := apischema.NewStructural(internal.Spec.Validation.OpenAPIV3Schema)
		if err != nil {
			celValidatorErr = fmt.Errorf("failed to create structural schema: %w", err)
			return
		}
		structuralSchema = structural

		celValidator = cel.NewValidator(structural, true, celconfig.PerCallLimit)
		if celValidator == nil {
			celValidatorErr = fmt.Errorf("no CEL validation rules found in CRD schema")
			return
		}
	})
	return celValidatorErr
}

// ValidateCEL validates an unstructured object against the CEL validation rules
// defined in the CRD's x-kubernetes-validations.
func ValidateCEL(ctx context.Context, obj *unstructured.Unstructured) error {
	err := initCELValidator()
	if err != nil {
		return err
	}

	errs, _ := celValidator.Validate(ctx, field.NewPath(""), structuralSchema, obj.Object, nil, celconfig.RuntimeCELCostBudget)
	if len(errs) > 0 {
		var errList []error
		for _, e := range errs {
			errList = append(errList, e)
		}
		return errors.Join(errList...)
	}
	return nil
}
