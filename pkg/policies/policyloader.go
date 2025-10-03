package policies

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	eedefaults "github.com/isovalent/hubble-fgs/pkg/defaults"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"

	"sigs.k8s.io/yaml"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
)

// Mocked by cmd/tetragon/TestLoadPolicies()
type Loader interface {
	OnTracingPolicy(ctx context.Context, fname string) error
	OnSandboxPolicy(ctx context.Context, fname string) error
	OnNetworkPolicy(bytes []byte) error
	OnAlertRule(bytes []byte, fname string) error
}

type defaultLoader struct {
	alertsManager alerts.RuleManager
	sm            *sensors.Manager
	log           *slog.Logger
}

func NewDefaultLoader(alertsManager alerts.RuleManager, sm *sensors.Manager, log *slog.Logger) Loader {
	return &defaultLoader{
		alertsManager: alertsManager,
		sm:            sm,
		log:           log,
	}
}

func (p *defaultLoader) OnTracingPolicy(ctx context.Context, fname string) error {
	f, err := filepath.Abs(filepath.Clean(fname))
	if err != nil {
		return err
	}

	tp, err := tracingpolicy.FromFile(f)
	if err != nil {
		return fmt.Errorf("failed to read (%s) tracing policy: %w", fname, err)
	}

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	if err != nil {
		return fmt.Errorf("failed to get sensors from (%s) parser policy: %w", fname, err)
	}

	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().Info("Added TracingPolicy with success",
		"TracingPolicy", fname,
		"metadata.namespace", namespace,
		"metadata.name", tp.TpName())

	return nil
}

func (p *defaultLoader) OnSandboxPolicy(ctx context.Context, fname string) error {
	return sandboxpolicy.AddSandboxPolicyFromYAML(ctx, p.log, p.sm, fname)
}

func (p *defaultLoader) OnNetworkPolicy(bytes []byte) error {
	return netpol.AddFromYAML(string(bytes))
}

func (p *defaultLoader) OnAlertRule(bytes []byte, fname string) error {
	obj, err := alerts.FromYAML(string(bytes))
	if err != nil {
		return err
	}
	ar, ok := obj.(*v1alpha1.AlertRule)
	if !ok {
		return fmt.Errorf("unexpected object type: %T", obj)
	}
	if ar.Spec.Export.Filename == "" {
		ar.Spec.Export.Filename = fname + ".log"
	}
	return p.alertsManager.AddAlertRule(ar)
}

func loadFromDir(ctx context.Context, dir string, loader Loader) error {
	var err error

	items, dirErr := os.ReadDir(dir)
	if dirErr != nil {
		return fmt.Errorf("policies dir is not readable: %w", dirErr)
	}
	for _, item := range items {
		// Skip directories (avoid recursive hell)
		if !item.IsDir() {
			fname := filepath.Join(dir, item.Name())
			bytes, readErr := os.ReadFile(fname)
			if readErr != nil {
				return fmt.Errorf("failed to read policy file %q: %w", fname, readErr)
			}
			// Discover policy kind
			var unstr unstructured.Unstructured
			if policyErr := yaml.UnmarshalStrict(bytes, &unstr); policyErr != nil {
				return fmt.Errorf("failed to parse policy file %q: %w", fname, policyErr)
			}
			kind := unstr.GetKind()
			switch kind {
			case "TracingPolicy", "TracingPolicyNamespaced":
				err = loader.OnTracingPolicy(ctx, fname)
				if err != nil {
					return fmt.Errorf("add "+kind+" failed: %w", err)
				}
			case "SandboxPolicy", "SandboxPolicyNamespaced":
				err = loader.OnSandboxPolicy(ctx, fname)
				if err != nil {
					return fmt.Errorf("add "+kind+" failed: %w", err)
				}
			case "TetragonNetworkPolicy":
				err = loader.OnNetworkPolicy(bytes)
				if err != nil {
					return fmt.Errorf("add "+kind+" failed: %w", err)
				}
			case "AlertRule":
				err = loader.OnAlertRule(bytes, fname)
				if err != nil {
					return fmt.Errorf("add "+kind+" failed: %w", err)
				}
			default:
				return fmt.Errorf("unknown kind: %s", kind)
			}
		}
	}
	return nil
}

func Load(ctx context.Context, alertsManager alerts.RuleManager, log *slog.Logger) error {
	sm := observer.GetSensorManager()
	loader := NewDefaultLoader(alertsManager, sm, log)

	err := loadTpFromDir(ctx, option.Config.TracingPolicyDir, loader, log)
	if err != nil {
		return err
	}

	err = netpol.AddFromDir(enterpriseOption.Config.NetworkPoliciesDir)
	if err != nil {
		return err
	}

	if len(option.Config.TracingPolicy) > 0 {
		err = loader.OnTracingPolicy(ctx, option.Config.TracingPolicy)
		if err != nil {
			return fmt.Errorf("add TracingPolicy failed: %w", err)
		}
	}

	if len(enterpriseOption.Config.NetworkPolicies) > 0 {
		for _, f := range enterpriseOption.Config.NetworkPolicies {
			err = netpol.AddFromFile(f)
			if err != nil {
				return fmt.Errorf("add TetragonNetworkPolicy failed: %w", err)
			}
		}
	}

	if len(enterpriseOption.Config.SandboxPolicies) > 0 {
		if enterpriseOption.Config.EnableSandboxPolicies {
			for _, fname := range enterpriseOption.Config.SandboxPolicies {
				err = loader.OnSandboxPolicy(ctx, fname)
				if err != nil {
					return err
				}
			}
		} else {
			logger.Fatal(log, "Sandbox policies specified but the feature is disabled", "sandboxpolicies", enterpriseOption.Config.SandboxPolicies)
		}
	}

	if enterpriseOption.Config.PoliciesDir != "" {
		if enterpriseOption.Config.PoliciesDir == eedefaults.DefaultPoliciesDir {
			// If the default directory does not exist then do not fail
			// Probably tetragon not fully installed, users did not create
			// /etc/tetragon/tetragon.policies.d/
			if _, err = os.Stat(enterpriseOption.Config.PoliciesDir); os.IsNotExist(err) {
				log.Info("Loading Policies from directory ignored, directory does not exist", "policies-dir", enterpriseOption.Config.PoliciesDir)
				return nil
			}
		}
		return loadFromDir(ctx, enterpriseOption.Config.PoliciesDir, loader)
	}
	return nil
}

func loadTpFromDir(ctx context.Context, dir string, loader Loader, log *slog.Logger) error {
	tpMaxDepth := 1
	tpFS := os.DirFS(dir)

	if dir == defaults.DefaultTpDir {
		// If the default directory does not exist then do not fail
		// Probably tetragon not fully installed, users did not create
		// /etc/tetragon/tetragon.tp.d/
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.Info("Loading Tracing Policies from directory ignored, directory does not exist", "tracing-policy-dir", dir)
			return nil
		}
	}

	err := fs.WalkDir(tpFS, ".", func(path string, d fs.DirEntry, err error) error {
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

		return loader.OnTracingPolicy(ctx, file)
	})

	return err
}
