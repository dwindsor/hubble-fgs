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
	"encoding/json"
	"io/ioutil"
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
		json.NewEncoder(ioutil.Discard),
		10,
		NewFakeK8sWatcher(pods),
		cilium.GetFakeCiliumState(),
		nil,
		nil)
	assert.NoError(t, err)
	pod, endpoint := pm.getPodInfo("container-id-not-found", &fgsAPI.MsgExecUnix{})
	assert.Nil(t, pod)
	assert.Nil(t, endpoint)
	pod, endpoint = pm.getPodInfo("aaaaaaa", &fgsAPI.MsgExecUnix{NSPID: 1234})
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
