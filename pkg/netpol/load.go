package netpol

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/netpol/library"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

var (
	tnpContext *crdutils.CRDContext[*v1alpha1.TetragonNetworkPolicy]
	tnpOnce    sync.Once
)

func getTNPContext() (*crdutils.CRDContext[*v1alpha1.TetragonNetworkPolicy], error) {
	var err error
	tnpOnce.Do(func() {
		tnpContext, err = crdutils.NewCRDContext[*v1alpha1.TetragonNetworkPolicy](&client.TetragonNetworkPolicyCRD.Definition)
	})
	return tnpContext, err
}

func FromYAML(data string) (*v1alpha1.TetragonNetworkPolicy, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal unstructured Tetragon network policy YAML: %w", err)
	}

	switch unstr.GetKind() {
	case v1alpha1.TNPKindDefinition:
		crdCtx, err := getTNPContext()
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve CRD context for TetragonNetworkPolicy: %w", err)
		}

		tnp, err := crdCtx.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return tnp, nil
	case v1alpha1.TNPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tetragon network policy not supported")
	default:
		return nil, nil
	}
}

func FromFile(path string) (*v1alpha1.TetragonNetworkPolicy, error) {
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, err
	}

	return FromYAML(string(data))
}

func LoadTNPFromFile(path string) error {
	np, err := FromFile(path)
	if err != nil {
		return fmt.Errorf("failed to parse %q TetragonNetworkPolicy: %w", path, err)
	}
	if np == nil {
		return nil
	}

	policies, err := ToTetragonNetworkPolicies(np)
	if err != nil {
		return fmt.Errorf("failed to convert TetragonNetworkPolicy %s to internal representation: %w", np.Name, err)
	}

	err = loadPolicy(&library.PolicyStory{
		Title:       np.Name,
		Rules:       make(map[string]uint64),
		CRDPolicy:   np,
		CRDNSPolicy: nil,
		IrPolicy:    policies,
	})
	if err != nil {
		return fmt.Errorf("failed to load TetragonNetworkPolicy: %w", err)
	}

	logger.GetLogger().Info("Added TetragonNetworkPolicy with success", "TetragonNetworkPolicy", path, "metadata.name", np.Name)

	return nil
}

func LoadTNPFromDir(dir string) error {
	if dir == "" {
		return nil
	}

	tpMaxDepth := 1
	npFS := os.DirFS(dir)

	// For now just use the same directory as TracingPolicies
	if dir == defaults.DefaultTpDir {
		// If the default directory does not exist then do not fail
		// Probably tetragon not fully installed, users did not create
		// /etc/tetragon/tetragon.tp.d/
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			logger.GetLogger().Info("Loading Tetragon Network Policies from directory ignored, directory does not exist",
				"tetragon-network-policy-dir", dir)
			return nil
		}
	}

	err := fs.WalkDir(npFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if strings.Count(path, string(os.PathSeparator)) >= tpMaxDepth {
				return fs.SkipDir
			}
			return nil
		}

		file := filepath.Join(dir, path)
		st, err := os.Stat(file)
		if err != nil {
			return err
		}

		if !st.Mode().IsRegular() {
			return nil
		}

		return LoadTNPFromFile(file)
	})

	return err
}

func Add(np *v1alpha1.TetragonNetworkPolicy) error {
	policies, err := ToTetragonNetworkPolicies(np)
	if err != nil {
		return fmt.Errorf("failed to convert TetragonNetworkPolicy %s to internal representation: %w", np.Name, err)
	}
	if np == nil {
		return nil
	}

	err = loadPolicy(&library.PolicyStory{
		Title:       np.Name,
		Rules:       make(map[string]uint64),
		CRDPolicy:   np,
		CRDNSPolicy: nil,
		IrPolicy:    policies,
	})
	if err != nil {
		return fmt.Errorf("failed to load TetragonNetworkPolicy: %w", err)
	}

	logger.GetLogger().Info("Added TetragonNetworkPolicy with success", "TetragonNetworkPolicy", np.Name)
	return nil
}

func Delete(np *v1alpha1.TetragonNetworkPolicy) {
	deleteNetworkPolicy(np)
}
