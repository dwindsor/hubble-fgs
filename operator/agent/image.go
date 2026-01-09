// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agent

import (
	"errors"

	"github.com/go-logr/logr"

	corev1 "k8s.io/api/core/v1"
)

func imagePullPolicy(log logr.Logger, config map[string]any, key string) corev1.PullPolicy {
	policy := corev1.PullPolicy(configValue(log, config, key, ""))
	switch policy {
	case corev1.PullAlways, corev1.PullNever, corev1.PullIfNotPresent:
		return policy
	}
	log.WithValues("key", key, "value", policy).Error(errors.New("could not resolve image pull policy"), "default value used instead")
	return corev1.PullIfNotPresent
}
