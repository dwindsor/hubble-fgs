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
	"net"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/endpoint/controllers"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	serviceClusterIPField = "spec.clusterIPs"
)

func ConfigureManager(ctx context.Context, manager *manager.ControllerManager) error {
	// Set up an index on the Service object for looking up services by their ClusterIP.
	err := manager.Manager.GetFieldIndexer().IndexField(ctx, &corev1.Service{}, serviceClusterIPField, getServiceClusterIPs)
	if err != nil {
		return err
	}
	if enterpriseOption.Config.EnableApplicationModel {
		serviceReconciler := controllers.NewServiceReconciler(manager.Manager.GetClient(), endpoint.MustGet())
		if err := serviceReconciler.SetupWithManager(manager.Manager); err != nil {
			return err
		}
	}
	return nil
}

func getServiceClusterIPs(rawObj client.Object) []string {
	return rawObj.(*corev1.Service).Spec.ClusterIPs
}

func GetSvcInfoOfIp(ip net.IP) *tetragon.Service {
	if !option.Config.EnableK8s {
		return nil
	}
	ctrlManager := manager.Get()
	serviceList := corev1.ServiceList{}
	listOptions := client.MatchingFields{serviceClusterIPField: ip.String()}
	err := ctrlManager.Manager.GetCache().List(context.Background(), &serviceList, &listOptions)
	if err != nil || len(serviceList.Items) == 0 {
		return nil
	}
	return &tetragon.Service{
		Name:      serviceList.Items[0].Name,
		Namespace: serviceList.Items[0].Namespace,
	}
}
