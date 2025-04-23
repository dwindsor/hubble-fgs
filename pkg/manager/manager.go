// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package manager

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/endpoint/controllers"
	"github.com/isovalent/hubble-fgs/pkg/model/dns"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	serviceClusterIPField = "spec.clusterIPs"
	podInfoIPField        = "status.podIPs"
)

var (
	instance KubernetesManager
	once     sync.Once
)

// KubernetesManager manages Kubernetes man.
type KubernetesManager interface {
	// GetControllerManager returns the underlying controller manager instance.
	GetControllerManager() *manager.ControllerManager
	// GetSvcInfoOfIp returns the Kubernetes service information for a given IP address.
	GetSvcInfoOfIp(ip net.IP) *tetragon.Service
	// FindPodInfoByIP returns the PodInfo objects associated with a given IP address.
	FindPodInfoByIP(ip string) ([]v1alpha1.PodInfo, error)
	// GetPodInfoOfNS returns all PodInfo objects in a given namespace.
	GetPodInfoOfNS(ns string) ([]v1alpha1.PodInfo, error)
}

var _ KubernetesManager = (*EnterpriseManager)(nil)
var _ KubernetesManager = (*FakeManager)(nil)

type EnterpriseManager struct {
	ossManager *manager.ControllerManager
}

func New(ctx context.Context) (KubernetesManager, error) {
	ossManager := manager.Get()
	// Set up an index on the Service object for looking up services by their ClusterIP.
	err := ossManager.Manager.GetFieldIndexer().IndexField(ctx, &corev1.Service{}, serviceClusterIPField, getServiceClusterIPs)
	if err != nil {
		return nil, err
	}
	err = ossManager.Manager.GetFieldIndexer().IndexField(ctx, &v1alpha1.PodInfo{}, podInfoIPField, getPodInfoIPs)
	if err != nil {
		return nil, err
	}
	if enterpriseOption.Config.EnableApplicationModel {
		serviceReconciler := controllers.NewServiceReconciler(ossManager.Manager.GetClient(), endpoint.MustGet())
		if err = serviceReconciler.SetupWithManager(ossManager.Manager); err != nil {
			return nil, err
		}
		if err := addPodInfoInformer(ctx, ossManager); err != nil {
			return nil, err
		}
	}
	ossManager.Start(ctx)
	return &EnterpriseManager{ossManager}, nil
}

func (em *EnterpriseManager) GetControllerManager() *manager.ControllerManager {
	return em.ossManager
}

func Get() KubernetesManager {
	once.Do(func() {
		if option.Config.EnableK8s {
			var err error
			logger.GetLogger().Info("Enabling Kubernetes controller-runtime manager")
			instance, err = New(context.Background())
			if err != nil {
				panic(err)
			}
		} else {
			logger.GetLogger().Info("Disabling Kubernetes controller-runtime manager")
			instance = &FakeManager{}
		}
	})
	return instance
}

func getServiceClusterIPs(rawObj client.Object) []string {
	return rawObj.(*corev1.Service).Spec.ClusterIPs
}

func getPodInfoIPs(rawObj client.Object) []string {
	var ips []string
	podInfo := rawObj.(*v1alpha1.PodInfo)
	for _, ip := range podInfo.Status.PodIPs {
		ips = append(ips, ip.IP)
	}
	return ips
}

func (em *EnterpriseManager) GetSvcInfoOfIp(ip net.IP) *tetragon.Service {
	serviceList := corev1.ServiceList{}
	listOptions := client.MatchingFields{serviceClusterIPField: ip.String()}
	err := em.ossManager.Manager.GetCache().List(context.Background(), &serviceList, &listOptions)
	if err != nil || len(serviceList.Items) == 0 {
		return nil
	}
	return &tetragon.Service{
		Name:      serviceList.Items[0].Name,
		Namespace: serviceList.Items[0].Namespace,
	}
}

func addPodInfoInformer(ctx context.Context, manager *manager.ControllerManager) error {
	informer, err := manager.Manager.GetCache().GetInformer(ctx, &v1alpha1.PodInfo{})
	if err != nil {
		return err
	}

	// The endpoint cache will be initialized here if it wasn't before. This
	// has to happen before the event handler is started and sensors are
	// loaded, to ensure we have maps and caches configured, and avoid racing
	// with sensor coming online.
	c := endpoint.MustGet()
	_, err = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			switch t := obj.(type) {
			case *v1alpha1.PodInfo:
				logger.GetLogger().Debug("Add Pod: %v", t)
				c.AddIpPodMap(t)
				dns.PodAdd(t)
			}
		},
		UpdateFunc: func(old interface{}, _ interface{}) {
			switch t := old.(type) {
			case *v1alpha1.PodInfo:
				logger.GetLogger().Debug("Update Pod: %v", t)
			}
		},
		DeleteFunc: func(old interface{}) {
			switch t := old.(type) {
			case *v1alpha1.PodInfo:
				logger.GetLogger().Debug("Delete Pod: %v", t)
				dns.PodRemove(t)
			}
		},
	})
	return err
}

func (em *EnterpriseManager) FindPodInfoByIP(ip string) ([]v1alpha1.PodInfo, error) {
	podInfoList := v1alpha1.PodInfoList{}
	listOptions := client.MatchingFields{podInfoIPField: ip}
	err := em.ossManager.Manager.GetCache().List(context.Background(), &podInfoList, &listOptions)
	if err != nil {
		return nil, err
	}
	return podInfoList.Items, err
}

func (em *EnterpriseManager) GetPodInfoOfNS(ns string) ([]v1alpha1.PodInfo, error) {
	podInfoList := v1alpha1.PodInfoList{}
	err := em.ossManager.Manager.GetCache().List(context.Background(), &podInfoList, &client.ListOptions{Namespace: ns})
	return podInfoList.Items, err
}

type FakeManager struct {
}

func (fm *FakeManager) GetControllerManager() *manager.ControllerManager {
	return nil
}

func (fm *FakeManager) GetSvcInfoOfIp(_ net.IP) *tetragon.Service {
	return nil
}

func (fm *FakeManager) FindPodInfoByIP(_ string) ([]v1alpha1.PodInfo, error) {
	return nil, fmt.Errorf("not implemented")
}

func (fm *FakeManager) GetPodInfoOfNS(_ string) ([]v1alpha1.PodInfo, error) {
	return nil, fmt.Errorf("not implemented")
}
