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

package servicemap

import (
	"context"
	"fmt"
	"net/netip"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/tetragon/pkg/logger"
)

// ServiceReconciler keeps the ServiceMap's service entries in sync with the
// cluster's Services. The map backs TetragonNetworkPolicy serviceSelector
// support.
type ServiceReconciler struct {
	Client client.Client
	Map    *ServiceMap
}

// Reconcile mirrors the live Service into the ServiceMap. A missing or
// headless Service has no ClusterIP to match on, so its entry is removed.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	svc := &corev1.Service{}
	if err := r.Client.Get(ctx, req.NamespacedName, svc); err != nil {
		if apierrors.IsNotFound(err) {
			r.Map.Delete(req.Namespace, req.Name)
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if svc.Spec.ClusterIP == corev1.ClusterIPNone || svc.Spec.ClusterIP == "" {
		// Headless services are not tracked; a service that switched to
		// headless must also drop its stale entry.
		r.Map.Delete(svc.Namespace, svc.Name)
		return ctrl.Result{}, nil
	}

	clusterIP, err := netip.ParseAddr(svc.Spec.ClusterIP)
	if err != nil {
		// Not expected for a non-headless service; nothing to track.
		logger.GetLogger().Warn("service has an unparseable ClusterIP; not tracking",
			"service", req.String(), "clusterIP", svc.Spec.ClusterIP, "error", err)
		return ctrl.Result{}, nil
	}

	var clusterIPs []netip.Addr
	for _, ipStr := range svc.Spec.ClusterIPs {
		if ip, err := netip.ParseAddr(ipStr); err == nil {
			clusterIPs = append(clusterIPs, ip)
		}
	}

	r.Map.AddOrUpdate(&ServiceInfo{
		Name:       svc.Name,
		Namespace:  svc.Namespace,
		ClusterIP:  clusterIP,
		ClusterIPs: clusterIPs,
		Labels:     svc.Labels,
		Selector:   svc.Spec.Selector,
	})
	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler under an explicit name: the
// endpoint-cache ServiceReconciler also watches corev1.Service on this manager,
// and the default name "service" would collide. No predicate: both label and
// spec changes feed serviceSelector matching, and core objects do not reliably
// bump metadata.generation.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("servicemap-service").
		For(&corev1.Service{}).
		Complete(r)
}

// EndpointSliceReconciler keeps the ServiceMap's endpoint lists in sync with
// the cluster's EndpointSlices.
type EndpointSliceReconciler struct {
	Client client.Client
	Map    *ServiceMap
}

// Reconcile mirrors the live EndpointSlice's ready endpoints into the
// ServiceMap. A deleted slice is left alone: its service attribution is only
// carried on the (now gone) object's labels, so endpoints are refreshed on the
// next slice update.
func (r *EndpointSliceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	eps := &discoveryv1.EndpointSlice{}
	if err := r.Client.Get(ctx, req.NamespacedName, eps); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// The owning service is carried on the slice's service-name label.
	svcName, ok := eps.Labels[discoveryv1.LabelServiceName]
	if !ok {
		return ctrl.Result{}, nil
	}

	r.Map.UpdateEndpoints(eps.Namespace, svcName, endpointsFromSlice(eps))
	return ctrl.Result{}, nil
}

// endpointsFromSlice extracts the ready endpoints of an EndpointSlice.
func endpointsFromSlice(eps *discoveryv1.EndpointSlice) []EndpointInfo {
	var endpoints []EndpointInfo
	for _, ep := range eps.Endpoints {
		if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
			continue
		}
		for _, addr := range ep.Addresses {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				continue
			}
			for _, port := range eps.Ports {
				if port.Port == nil {
					continue
				}
				protocol := "TCP"
				if port.Protocol != nil {
					protocol = string(*port.Protocol)
				}
				podName := ""
				if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" {
					podName = ep.TargetRef.Name
				}
				endpoints = append(endpoints, EndpointInfo{
					IP:       ip,
					Port:     *port.Port,
					Protocol: protocol,
					PodName:  podName,
				})
			}
		}
	}
	return endpoints
}

// SetupWithManager registers the reconciler under an explicit name for
// symmetry with the Service controller. No predicate: endpoint readiness
// changes are the signal.
func (r *EndpointSliceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("servicemap-endpointslice").
		For(&discoveryv1.EndpointSlice{}).
		Complete(r)
}

// RegisterReconcilers installs the Service and EndpointSlice reconcilers that
// keep sm in sync. Setup only fails on programming errors (name collision, type
// not in scheme), so both registrations are fatal.
func RegisterReconcilers(mgr ctrl.Manager, sm *ServiceMap) error {
	logger.GetLogger().Info("Initializing ServiceMap reconcilers for TNP serviceSelector support")
	if err := (&ServiceReconciler{Client: mgr.GetClient(), Map: sm}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup ServiceMap service reconciler: %w", err)
	}
	if err := (&EndpointSliceReconciler{Client: mgr.GetClient(), Map: sm}).SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup ServiceMap endpointslice reconciler: %w", err)
	}
	return nil
}
