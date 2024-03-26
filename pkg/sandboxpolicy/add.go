package sandboxpolicy

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"
)

func AddSandboxPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager, obj interface{}) error {
	var tp tracingpolicy.TracingPolicy

	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		var err error
		log = log.WithFields(logrus.Fields{
			"sandbox-policy-name": sp.ObjectMeta.Name,
		})
		tp, err = ToTracingPolicy(sp)
		if err != nil {
			log.WithError(err).Warn("AddSandboxPolicy: failed to convert to tracing policy")
			return fmt.Errorf("failed to convert sandboxpolicy to tracing policy: %w", err)
		}

	case *v1alpha1.SandboxPolicyNamespaced:
		var err error
		log = log.WithFields(logrus.Fields{
			"sandbox-policy-name":      sp.ObjectMeta.Name,
			"sandbox-policy-namespace": sp.ObjectMeta.Namespace,
		})
		tp, err = ToTracingPolicyNamespaced(sp)
		if err != nil {
			log.WithError(err).Warn("AddSandboxPolicy: failed to convert to tracing policy")
			return fmt.Errorf("failed to convert namespaced sandboxpolicy to tracing policy: %w", err)
		}

	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addSandboxPolicy: invalid type")
		return fmt.Errorf("invalid sandbox policy type: %T", obj)
	}

	log.WithFields(logrus.Fields{
		"tp-name": tp.TpName(),
		"tp-info": tp.TpInfo(),
	}).Info("adding sandbox policy")
	return s.AddTracingPolicy(ctx, tp)
}
