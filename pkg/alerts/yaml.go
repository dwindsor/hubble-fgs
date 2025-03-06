//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var (
	arContext *crdutils.CRDContext[*v1alpha1.AlertRule]
	arOnce    sync.Once
)

func FromYAML(data string) (crdutils.CRDObject, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	switch unstr.GetKind() {
	case "AlertRule":
		crdCtx, err := getARContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for AlertRule: %w", err)
		}
		obj, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	default:
		return nil, fmt.Errorf("unknown CRD kind: %s", unstr.GetKind())
	}
}

func getARContext() (*crdutils.CRDContext[*v1alpha1.AlertRule], error) {
	var err error
	arOnce.Do(func() {
		arContext, err = crdutils.NewCRDContext[*v1alpha1.AlertRule](&client.AlertRuleCRD.Definition)
	})
	return arContext, err
}
