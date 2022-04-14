//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package watcher

import (
	coreV1 "k8s.io/api/core/v1"
)

func getExecCommand(probe *coreV1.Probe) []string {
	if probe != nil && probe.Exec != nil {
		return probe.Exec.Command
	}
	return nil
}

func getProbes(pod *coreV1.Pod, containerStatus *coreV1.ContainerStatus) ([]string, []string) {
	for _, container := range pod.Spec.Containers {
		if container.Name == containerStatus.Name {
			return getExecCommand(container.LivenessProbe), getExecCommand(container.ReadinessProbe)
		}
	}
	return nil, nil
}
