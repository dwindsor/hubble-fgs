//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build nok8s

package alerts

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
)

func RuleFromYAML(data string) (*v1alpha1.AlertRule, error) {
	kind, jsonBytes, err := nok8s.ParseK8sObj(data)
	if err != nil {
		return nil, err
	}

	switch kind {
	case "AlertRule":
		var ar v1alpha1.AlertRule
		if err := json.Unmarshal(jsonBytes, &ar); err != nil {
			return nil, fmt.Errorf("failed to unmarshal AlertRule: %w", err)
		}
		return &ar, nil
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}
