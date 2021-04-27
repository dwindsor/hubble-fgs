// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	fgsAPI "github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/cilium"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProcessManager_getPodInfo(t *testing.T) {
	podA := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "namespace-a",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "pod-a-container-a-name",
					Image:       "pod-a-image-a-name",
					ImageID:     "pod-a-image-a-id",
					ContainerID: "docker://aaaaaaaaaaaaaaa",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: v1.Time{
								Time: time.Unix(1, 2),
							},
						},
					},
				},
			},
		},
	}
	pods := []interface{}{&podA}
	pm, err := NewProcessManager(
		logrus.New(),
		10,
		NewFakeK8sWatcher(pods),
		cilium.GetFakeCiliumState(),
		false, false)
	assert.NoError(t, err)
	pod, endpoint := pm.getPodInfo("container-id-not-found", "", "", 0)
	assert.Nil(t, pod)
	assert.Nil(t, endpoint)
	pod, endpoint = pm.getPodInfo("aaaaaaa", "", "", 1234)
	assert.Equal(t,
		&fgs.Pod{
			Namespace: podA.Namespace,
			Name:      podA.Name,
			Container: &fgs.Container{
				Id:   podA.Status.ContainerStatuses[0].ContainerID,
				Name: podA.Status.ContainerStatuses[0].Name,
				Image: &fgs.Image{
					Id:   podA.Status.ContainerStatuses[0].ImageID,
					Name: podA.Status.ContainerStatuses[0].Image,
				},
				StartTime: &timestamp.Timestamp{
					Seconds: int64(podA.Status.ContainerStatuses[0].State.Running.StartedAt.Second()),
					Nanos:   int32(podA.Status.ContainerStatuses[0].State.Running.StartedAt.Nanosecond()),
				},
				Pid: &wrappers.UInt32Value{Value: 1234},
			},
		}, pod)
	assert.Nil(t, endpoint)
}

func TestProcessManager_getPodInfoMaybeExecProbe(t *testing.T) {
	var podA = corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "namespace-a",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "pod-a-container-a-name",
					LivenessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							Exec: &corev1.ExecAction{
								Command: []string{"command", "arg-a", "arg-b"},
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "pod-a-container-a-name",
					ContainerID: "docker://aaaaaaaaaaaaaaa",
				},
			},
		},
	}
	pods := []interface{}{&podA}
	pm, err := NewProcessManager(
		logrus.New(),
		10,
		NewFakeK8sWatcher(pods),
		cilium.GetFakeCiliumState(),
		false, false)
	assert.NoError(t, err)
	pod, endpoint := pm.getPodInfo("aaaaaaa", "/bin/command", "arg-a arg-b", 1234)
	assert.Equal(t,
		&fgs.Pod{
			Namespace: podA.Namespace,
			Name:      podA.Name,
			Container: &fgs.Container{
				Id:             podA.Status.ContainerStatuses[0].ContainerID,
				Name:           podA.Status.ContainerStatuses[0].Name,
				Image:          &fgs.Image{},
				Pid:            &wrappers.UInt32Value{Value: 1234},
				MaybeExecProbe: true,
			},
		}, pod)
	assert.Nil(t, endpoint)
}

func TestProcessManager_GetProcessExec(t *testing.T) {
	pm, err := NewProcessManager(
		logrus.New(),
		10,
		NewFakeK8sWatcher(nil),
		cilium.GetFakeCiliumState(),
		false, false)
	assert.NoError(t, err)
	procInternal := pm.Add(&fgsAPI.MsgExecveEventUnix{
		Common: fgsAPI.MsgCommon{
			Ktime: 1234,
		},
		Capabilities: fgsAPI.MsgCapabilities{
			Permitted:   1,
			Effective:   1,
			Inheritable: 1,
		},
		Process: fgsAPI.MsgExecUnix{
			PID: 5678,
		},
	})
	assert.Nil(t, pm.GetProcessExec(procInternal).Process.Cap)

	// cap field should be set with enable-process-cred flag.
	pm.enableProcessCred = true
	assert.Equal(t,
		&fgs.Capabilities{
			Permitted:   []fgs.CapabilitiesType{fgs.CapabilitiesType_CAP_CHOWN},
			Effective:   []fgs.CapabilitiesType{fgs.CapabilitiesType_CAP_CHOWN},
			Inheritable: []fgs.CapabilitiesType{fgs.CapabilitiesType_CAP_CHOWN},
		},
		pm.GetProcessExec(procInternal).Process.Cap)
}

func Test_getNodeNameForExport(t *testing.T) {
	assert.Equal(t, "", getNodeNameForExport())
	assert.NoError(t, os.Setenv("NODE_NAME", "from-node-name"))
	assert.Equal(t, "from-node-name", getNodeNameForExport())
	assert.NoError(t, os.Setenv("HUBBLE_NODE_NAME", "from-hubble-node-name"))
	assert.Equal(t, "from-hubble-node-name", getNodeNameForExport())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
	assert.NoError(t, os.Unsetenv("HUBBLE_NODE_NAME"))
}

func TestProcessManager_GetProcessID(t *testing.T) {
	assert.NoError(t, os.Setenv("NODE_NAME", "my-node"))
	pm, err := NewProcessManager(
		logrus.New(),
		10,
		NewFakeK8sWatcher([]interface{}{}),
		cilium.GetFakeCiliumState(),
		false, false)
	assert.NoError(t, err)
	id := pm.GetProcessID(1, 2)
	decoded, err := base64.StdEncoding.DecodeString(id)
	assert.NoError(t, err)
	assert.Equal(t, "my-node:2:1", string(decoded))
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
}

func Test_getBinaryAbsolutePath(t *testing.T) {
	assert.Equal(t, "/usr/bin/cat", getBinaryAbsolutePath("/usr/bin/cat", "/tmp"))
	assert.Equal(t, "/usr/bin/cat", getBinaryAbsolutePath("./bin/cat", "/usr"))
	assert.Equal(t, "/usr/bin/cat", getBinaryAbsolutePath("../usr/bin/cat", "/etc"))
	assert.Equal(t, "/usr/bin/cat", getBinaryAbsolutePath("../../bin/cat", "/usr/local/bin"))
}
