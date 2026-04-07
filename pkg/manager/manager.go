// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !nok8s

package manager

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/watcher/conf"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/tetragon/api/v1/tetragon"
	enterpriseClient "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/endpoint/controllers"
	"github.com/isovalent/hubble-fgs/pkg/netpol/servicemap"
	"github.com/isovalent/hubble-fgs/pkg/netpolstate"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	enterpriseConf "github.com/isovalent/hubble-fgs/pkg/watcher/conf"
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
	// GetService returns the Kubernetes service for given namespace and name.
	GetService(namespace, name string) *corev1.Service
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
	// Overwrite the k8s config in oss watcher conf with the one from enterprise
	// So that we can extend k8s auth mechanisms for switches
	conf.K8sConfig = enterpriseConf.K8sConfig
	ossManager := manager.Get()
	// This looks a bit off, starting controller-runtime manager before adding
	// controllers, but we need to start the manager to be able to start an
	// informer for CRDs. Adding controllers after starting the manager is ok
	// according to https://github.com/kubernetes-sigs/controller-runtime/issues/1994.
	ossManager.Start(ctx)

	// Set the k8s reader for namespace label lookups used by namespaceSelector
	netpolstate.Get().SetK8sReader(ossManager.Manager.GetCache())

	// Ensure Namespace objects are cached for namespace label lookups
	// This is needed for namespaceSelector matching in TetragonNetworkPolicy
	_, err := ossManager.Manager.GetCache().GetInformer(ctx, &corev1.Namespace{})
	if err != nil {
		return nil, err
	}

	if !enterpriseOption.InClusterControlPlaneEnabled() {
		return &EnterpriseManager{ossManager}, nil
	}
	// Wait for tetragon-operator to create CRDs
	enabledCRDs := getEnabledCRDs()
	if len(enabledCRDs) > 0 {
		if err := ossManager.WaitCRDs(ctx, enabledCRDs); err != nil {
			return nil, err
		}
	}
	// Set up an index on the Service object for looking up services by their ClusterIP.
	err = ossManager.Manager.GetFieldIndexer().IndexField(ctx, &corev1.Service{}, serviceClusterIPField, getServiceClusterIPs)
	if err != nil {
		return nil, err
	}
	if option.Config.EnablePodInfo {
		err = ossManager.Manager.GetFieldIndexer().IndexField(ctx, &v1alpha1.PodInfo{}, podInfoIPField, getPodInfoIPs)
		if err != nil {
			return nil, err
		}
	}
	if enterpriseOption.Config.EnableApplicationModel {
		serviceReconciler := controllers.NewServiceReconciler(ossManager.Manager.GetClient(), endpoint.MustGet())
		if err = serviceReconciler.SetupWithManager(ossManager.Manager); err != nil {
			return nil, fmt.Errorf("failed to setup Service reconciler: %w", err)
		}
		if err := addPodInfoInformer(ctx, ossManager); err != nil {
			return nil, err
		}
		state := netpolstate.Get()
		sm := servicemap.NewServiceMap(state)
		if err := servicemap.AddServiceInformer(ctx, ossManager, sm); err != nil {
			return nil, err
		}
		// Set the ServiceMap on the realized state for policy lookups
		state.SetServiceMap(sm)
	}
	return &EnterpriseManager{ossManager}, nil
}

func (em *EnterpriseManager) GetControllerManager() *manager.ControllerManager {
	return em.ossManager
}

func Get() KubernetesManager {
	once.Do(func() {
		if enterpriseOption.K8SControlPlaneEnabled() {
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

func (em *EnterpriseManager) GetService(namespace, name string) *corev1.Service {
	svc := &corev1.Service{}
	err := em.ossManager.Manager.GetCache().Get(context.Background(), client.ObjectKey{Namespace: namespace, Name: name}, svc)
	if err != nil {
		return nil
	}
	return svc
}

func (em *EnterpriseManager) GetSvcInfoOfIp(ip net.IP) *tetragon.Service {
	serviceList := corev1.ServiceList{}
	listOptions := client.MatchingFields{serviceClusterIPField: ip.String()}
	err := em.ossManager.Manager.GetCache().List(context.Background(), &serviceList, &listOptions)
	if err != nil || len(serviceList.Items) == 0 {
		return nil
	}
	return &tetragon.Service{
		Name:           serviceList.Items[0].Name,
		Namespace:      serviceList.Items[0].Namespace,
		Type:           tetragon.ServiceKind_SERVICE_KIND_CLUSTER_IP,
		SelectorLabels: serviceList.Items[0].Spec.Selector,
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
				logger.GetLogger().Debug(fmt.Sprintf("Add Pod: %v", t))
				c.AddIpPodMap(t)
				if polErr := netpolstate.Get().PodAdd(t); polErr != nil {
					logger.GetLogger().Error(fmt.Sprintf("Pod add error: %v", polErr))
				}
			}
		},
		UpdateFunc: func(old interface{}, _ interface{}) {
			switch t := old.(type) {
			case *v1alpha1.PodInfo:
				logger.GetLogger().Debug(fmt.Sprintf("Update Pod: %v", t))
			}
		},
		DeleteFunc: func(old interface{}) {
			switch t := old.(type) {
			case *v1alpha1.PodInfo:
				logger.GetLogger().Debug(fmt.Sprintf("Delete Pod: %v", t))
				if err := netpolstate.Get().PodRemove(t); err != nil {
					logger.GetLogger().Error(fmt.Sprintf("Pod remove error: %v", err))
				}
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
	Service map[client.ObjectKey]*corev1.Service
}

func NewFakeManager() *FakeManager {
	return &FakeManager{
		Service: make(map[client.ObjectKey]*corev1.Service),
	}
}
func (fm *FakeManager) GetControllerManager() *manager.ControllerManager {
	return nil
}

func (fm *FakeManager) AddService(svc *corev1.Service) {
	fm.Service[client.ObjectKey{Namespace: svc.Namespace, Name: svc.Name}] = svc
}

func (fm *FakeManager) GetService(namespace, name string) *corev1.Service {
	return fm.Service[client.ObjectKey{Namespace: namespace, Name: name}]
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

func getEnabledCRDs() map[string]struct{} {
	crds := make(map[string]struct{})

	if option.Config.EnablePodInfo {
		crds[v1alpha1.PIName] = struct{}{}
	}

	if enterpriseOption.Config.EnablePolicyK8sWatcher {
		// NB(anna): Check this option for OSS compatibility, but it's not
		// recommended to use it to disable watching TracingPolicy in EE.
		// Use --enable-policy-k8swatcher=false instead.
		if option.Config.EnableTracingPolicyCRD {
			crds[v1alpha1.TPName] = struct{}{}
			crds[v1alpha1.TPNamespacedName] = struct{}{}
		}
		if enterpriseOption.Config.EnableSandboxPolicies {
			crds[enterpriseClient.SandboxPolicyCRD.ResName] = struct{}{}
			crds[enterpriseClient.SandboxPolicyNamespacedCRD.ResName] = struct{}{}
		}
	}

	crds[enterpriseClient.AlertRuleCRD.ResName] = struct{}{}
	crds[enterpriseClient.TetragonNetworkPolicyCRD.ResName] = struct{}{}
	crds[enterpriseClient.TetragonNetworkPolicyNamespacedCRD.ResName] = struct{}{}
	return crds
}
