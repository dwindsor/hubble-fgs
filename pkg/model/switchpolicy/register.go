package switchpolicy

import (
	"log/slog"
	"sync"

	osscrdutils "github.com/cilium/tetragon-oss/pkg/k8s/crdutils"
	"github.com/cilium/tetragon/pkg/crdutils"

	"github.com/isovalent/ipa/k8s"
	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
)

var (
	snpContext *crdutils.CRDContext[*v1alpha1.SmartSwitchNetworkPolicy]
	snpOnce    sync.Once

	SmartSwitchNetworkPolicyCRD = osscrdutils.NewCRDBytes(
		slog.Default(),
		"SmartSwitchNetworkPolicy/v1alpha1",
		"smartswitchnetworkpolicies.isovalent.com",
		k8s.CRDsv1Alpha1SmartSwitchNetworkPolicy,
	)
)

func getSNPContext() (*crdutils.CRDContext[*v1alpha1.SmartSwitchNetworkPolicy], error) {
	var err error
	snpOnce.Do(func() {
		snpContext, err = crdutils.NewCRDContext[*v1alpha1.SmartSwitchNetworkPolicy](&SmartSwitchNetworkPolicyCRD.Definition)
	})
	return snpContext, err
}
