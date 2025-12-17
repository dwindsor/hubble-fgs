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
	isovalentv1alpha1 "github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

const (
	// AnnotationPrefix is the common prefix for annotations for smart switch network policies.
	AnnotationPrefix = isovalentv1alpha1.SNPName

	// AnnotationStaging annotation marks the policy as a staging policy to validate
	// changes to a deployed policy.
	//
	// A policy with a staging annotation set is never deployed and
	// only validated.
	//
	// The value is the name of the deployed policy to compare against.
	AnnotationStaging = AnnotationPrefix + "/staging"
)
