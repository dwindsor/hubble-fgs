//go:build nok8s

package sandboxpolicy

import (
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type SandboxTracingPolicyNamespaced tracingpolicy.TracingPolicy

func FromYAML(data string) (any, error) {
	kind, jsonBytes, err := nok8s.ParseK8sObj(data)
	if err != nil {
		return nil, err
	}

	switch kind {
	case "SandboxPolicy":
		var sp v1alpha1.SandboxPolicy
		if err := json.Unmarshal(jsonBytes, &sp, json.RejectUnknownMembers(true)); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Sandboxpolicy: %w", err)
		}
		return &sp, nil
	case "SandboxPolicyNamespaced":
		return nil, fmt.Errorf("namespaced sandbox policies not supported in non-k8s builds: %s", kind)
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}

func ToTracingPolicyNamespaced(p any) (SandboxTracingPolicyNamespaced, error) {
	return nil, errors.New("namespaced sandboxpolicy not supported in nok8s build")
}
