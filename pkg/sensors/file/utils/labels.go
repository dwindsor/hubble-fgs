//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"strings"

	"github.com/cilium/tetragon/pkg/logger"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	InvalidLabel = iota + 1
	NamespaceLabel
	AppLabel
)

var (
	ValidLabels = map[string]int{
		"io.kubernetes.pod.namespace":     NamespaceLabel,
		"k8s:io.kubernetes.pod.namespace": NamespaceLabel,
		"io.kubernetes.pod.app":           AppLabel,
		"k8s:io.kubernetes.pod.app":       AppLabel,
	}
)

func getLabel(label string) int {
	if v, ok := ValidLabels[label]; ok {
		return v
	}
	return InvalidLabel
}

func matchLabelSelectorRequirement(spec slimv1.LabelSelectorRequirement, podNs, podName string) bool {
	switch tp := getLabel(spec.Key); tp {
	case NamespaceLabel, AppLabel:
		matchVal := podNs // tp == NamespaceLabel
		if tp == AppLabel {
			matchVal = podName
		}

		match := false
		for _, value := range spec.Values {
			switch tp {
			case AppLabel:
				// in the case of app we check for prefix or full match
				match = match || strings.HasPrefix(matchVal, value)
			case NamespaceLabel:
				// in the case of namespace we check for full match
				match = match || (matchVal == value)
			}
		}

		switch op := spec.Operator; op {
		case "In":
			return match
		case "NotIn":
			return !match
		default:
			logger.GetLogger().WithField("op", op).Warnf("Unexpected Operator in matchLabels")
			return false
		}
	default:
		logger.GetLogger().WithField("label", spec.Key).Warnf("Unexpected InvalidLabel in matchLabels")
		return false
	}
}

func matchExpressions(spec []slimv1.LabelSelectorRequirement, podNs, podName string) bool {
	if len(spec) == 0 {
		return true
	}
	result := true
	for _, expr := range spec {
		result = result && matchLabelSelectorRequirement(expr, podNs, podName)
	}
	return result
}

func matchLabels(labels map[string]slimv1.MatchLabelsValue, podNs, podName string) bool {
	if len(labels) == 0 {
		return true
	}
	for key, val := range labels {
		switch tp := getLabel(key); tp {
		case NamespaceLabel, AppLabel:
			matchVal := podNs // tp == NamespaceLabel
			if tp == AppLabel {
				matchVal = podName
			}

			match := false
			switch tp {
			case AppLabel:
				// in the case of app we check for prefix or full match
				match = strings.HasPrefix(matchVal, val)
			case NamespaceLabel:
				// in the case of namespace we check for full match
				match = (matchVal == val)
			}

			if !match {
				return false
			}
		default:
			logger.GetLogger().WithField("label", key).Warnf("Unexpected InvalidLabel in matchLabels")
			return false
		}
	}
	return true
}

func MatchPodSelector(s *slimv1.LabelSelector, podNs, podName string) bool {
	if s == nil {
		return false
	}
	return matchExpressions(s.MatchExpressions, podNs, podName) && matchLabels(s.MatchLabels, podNs, podName)
}
