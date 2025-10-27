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
