package netpol

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

func fromYAML(data string) (*v1alpha1.TetragonNetworkPolicy, error) {
	var unstr unstructured.Unstructured

	if err := yaml.Unmarshal([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal unstructured Tetragon network policy YAML: %w", err)
	}
	kind := unstr.GetKind()
	switch kind {
	case v1alpha1.TNPKindDefinition:
		var tnp v1alpha1.TetragonNetworkPolicy

		if err := yaml.UnmarshalStrict([]byte(data), &tnp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Tetragon network policy YAML: %w", err)
		}
		return &tnp, nil
	case v1alpha1.TNPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tetragon network policy not supported")
	default:
		return nil, nil
	}
}

func fromFile(path string) (*v1alpha1.TetragonNetworkPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return fromYAML(string(data))
}

func addNetworkPolicy(_ context.Context, file string) error {
	f, err := filepath.Abs(filepath.Clean(file))
	if err != nil {
		return err
	}

	np, err := fromFile(f)
	if err != nil {
		return fmt.Errorf("failed to read (%s) tetragon network policy: %w", file, err)
	}
	if np == nil {
		return nil
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"TetragonNetworkPolicy": file,
		"metadata.name":         np.Name,
	}).Info("Added TetragonNetworkPolicy with success")

	return nil
}

func LoadTNPFromFile(ctx context.Context, file string) error {
	return addNetworkPolicy(ctx, file)
}

func LoadTNPFromDir(ctx context.Context, dir string) error {
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
			logger.GetLogger().WithField("tetragon-network-policy-dir", dir).Info("Loading Tetragon Network Policies from directory ignored, directory does not exist")
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

		return addNetworkPolicy(ctx, file)
	})

	return err
}
