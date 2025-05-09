// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build integration

package manager

import (
	"fmt"
	"testing"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

type ManagerTestSuite struct {
	suite.Suite
	testEnv *envtest.Environment
	manager KubernetesManager
}

func (suite *ManagerTestSuite) SetupSuite() {
	option.Config.EnableK8s = true
	option.Config.EnablePodInfo = true
	useExistingCluster := true
	suite.testEnv = &envtest.Environment{
		UseExistingCluster: &useExistingCluster,
	}
	_, err := suite.testEnv.Start()
	assert.NoError(suite.T(), err)
	suite.manager = Get()
}

func (suite *ManagerTestSuite) TestGetPodInfoOfNS() {
	ns := "kube-system"
	pods, err := suite.manager.GetPodInfoOfNS(ns)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), pods)
	for _, pod := range pods {
		assert.Equal(suite.T(), ns, pod.Namespace)
	}
}

func (suite *ManagerTestSuite) TestFindPodInfoByIP() {
	ns := "kube-system"
	pods, err := suite.manager.GetPodInfoOfNS(ns)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), pods)
	// Find a pod that is not on host network
	var podIndex int
	for i, pod := range pods {
		if !pod.Spec.HostNetwork {
			podIndex = i
			break
		}
	}
	ip := pods[podIndex].Status.PodIP
	pod, err := suite.manager.FindPodInfoByIP(ip)
	for _, p := range pod {
		fmt.Println(p.Namespace, p.Name)
	}
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), pod, 1)
	assert.Equal(suite.T(), pods[podIndex].Namespace, pod[0].Namespace)
	assert.Equal(suite.T(), pods[podIndex].Name, pod[0].Name)
}

func (suite *ManagerTestSuite) TearDownSuite() {
	assert.NoError(suite.T(), suite.testEnv.Stop())
}

func TestControllerSuite(t *testing.T) {
	suite.Run(t, new(ManagerTestSuite))
}
