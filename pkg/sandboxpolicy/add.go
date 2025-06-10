package sandboxpolicy

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

var (
	spContext  *crdutils.CRDContext[*v1alpha1.SandboxPolicy]
	spOnce     sync.Once
	spnContext *crdutils.CRDContext[*v1alpha1.SandboxPolicyNamespaced]
	spnOnce    sync.Once
)

func AddSandboxPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager, obj interface{}) error {
	var tp tracingpolicy.TracingPolicy

	switch sp := obj.(type) {
	case *v1alpha1.SandboxPolicy:
		var err error
		log = log.With("sandbox-policy-name", sp.Name)
		tp, err = ToTracingPolicy(sp)
		if err != nil {
			log.Warn("AddSandboxPolicy: failed to convert to tracing policy", logfields.Error, err)
			return fmt.Errorf("failed to convert sandboxpolicy to tracing policy: %w", err)
		}

	case *v1alpha1.SandboxPolicyNamespaced:
		var err error
		log = log.With("sandbox-policy-name", sp.Name, "sandbox-policy-namespace", sp.Namespace)
		tp, err = ToTracingPolicyNamespaced(sp)
		if err != nil {
			log.Warn("AddSandboxPolicy: failed to convert to tracing policy", logfields.Error, err)
			return fmt.Errorf("failed to convert namespaced sandboxpolicy to tracing policy: %w", err)
		}

	default:
		log.Warn("addSandboxPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return fmt.Errorf("invalid sandbox policy type: %T", obj)
	}

	log.Info("adding sandbox policy", "tp-name", tp.TpName(), "tp-info", tp.TpInfo())
	return s.AddTracingPolicy(ctx, tp)
}

func AddSandboxPolicyFromYAML(
	ctx context.Context,
	log logger.FieldLogger,
	s *sensors.Manager,
	fname string,
) error {
	fname, err := filepath.Abs(filepath.Clean(fname))
	if err != nil {
		return err
	}

	data, err := os.ReadFile(fname)
	if err != nil {
		return err
	}

	sp, err := FromYAML(string(data))
	if err != nil {
		return err
	}

	log = log.With("from-yaml", true)
	return AddSandboxPolicy(ctx, log, s, sp)
}

// FromYAML inspects the YAML input to determine the kind, then dispatches to
// the generic FromYAML function.
func FromYAML(data string) (crdutils.CRDObject, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	switch unstr.GetKind() {
	case "SandboxPolicy":
		crdCtx, err := getSPContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for SandboxPolicy: %w", err)
		}
		obj, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	case "SandboxPolicyNamespaced":
		crdCtx, err := getSPNContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for SandboxPolicyNamespaced: %w", err)
		}
		obj, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	default:
		return nil, fmt.Errorf("unknown CRD kind: %s", unstr.GetKind())
	}
}

func getSPContext() (*crdutils.CRDContext[*v1alpha1.SandboxPolicy], error) {
	var err error
	spOnce.Do(func() {
		spContext, err = crdutils.NewCRDContext[*v1alpha1.SandboxPolicy](&client.SandboxPolicyCRD.Definition)
	})
	return spContext, err
}

func getSPNContext() (*crdutils.CRDContext[*v1alpha1.SandboxPolicyNamespaced], error) {
	var err error
	spnOnce.Do(func() {
		spnContext, err = crdutils.NewCRDContext[*v1alpha1.SandboxPolicyNamespaced](&client.SandboxPolicyNamespacedCRD.Definition)
	})
	return spnContext, err
}
