//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package metrics

import (
	oss "github.com/cilium/tetragon/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
)

var (
	ExampleDNSNamesLabel   = "example.com,www.example.com"
	ExamplePodLabels       = []string{"example-namespace", "example-workload", "example-pod"}
	ExampleDstLabels       = append(ExamplePodLabels, ExampleDNSNamesLabel)
	ExampleDomain          = "example.org"
	ExampleIPLabel         = "10.1.0.0"
	ExampleSocketDstLabels = append(ExampleDstLabels, ExampleIPLabel)
	ExampleLatencyBuckets  = []string{"100", "1000", "2500", "5000", "7500", "9000", "9900", "+Inf"}
	ExampleNodeLabel       = "example-nodename"
	ExampleDir             = "/etc/example/"
	ExampleFile            = "/bin/example"
	ExampleFileDigest      = "HASH_ALGO_SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

func DeleteMetricsForPod(pod *corev1.Pod) {
	oss.DeleteMetricsForPod(pod)
	// Delete metrics matching the deleted pod on the destination labels too.
	for _, metric := range oss.ListMetricsWithPod() {
		metric.DeletePartialMatch(prometheus.Labels{
			"dstpod":       pod.Name,
			"dstnamespace": pod.Namespace,
		})
	}
}

func StartPodDeleteHandler() {
	queue := oss.GetPodQueue()
	for {
		pod, quit := queue.Get()
		if quit {
			return
		}
		DeleteMetricsForPod(pod.(*corev1.Pod))
	}
}
