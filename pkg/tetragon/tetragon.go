// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package tetragon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policystore"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/server/eventlog"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	// Imported to allow sensors to be initialized inside init().
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"
	// Add enterprise-specific filters to the global registry
	_ "github.com/isovalent/hubble-fgs/pkg/filters"
	// sensor init
	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"

	splunkV1 "github.com/isovalent/ipa/splunk/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/mandate"
	mandatesrv "github.com/isovalent/hubble-fgs/pkg/mandate/server"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	register "github.com/isovalent/hubble-fgs/pkg/node"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/policies"
	processcacheclean "github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/rule"
	"github.com/isovalent/hubble-fgs/pkg/sensors/powershell"
	eeserver "github.com/isovalent/hubble-fgs/pkg/server"
	splunkHec "github.com/isovalent/hubble-fgs/pkg/splunk/hec"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/certloader"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/pidfile"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
)

var (
	log = logger.GetLogger()
)

func getExportFilters() ([]*tetragon.Filter, []*tetragon.Filter, error) {
	allowList, err := filters.ParseFilterList(viper.GetString(option.KeyExportAllowlist), viper.GetBool(option.KeyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	denyList, err := filters.ParseFilterList(viper.GetString(option.KeyExportDenylist), viper.GetBool(option.KeyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	return allowList, denyList, nil
}

func getFieldFilters() ([]*tetragon.FieldFilter, error) {
	fieldFilters := viper.GetString(option.KeyFieldFilters)

	filters, err := fieldfilters.ParseFieldFilterList(fieldFilters)
	if err != nil {
		return nil, err
	}

	return filters, nil
}

func setRedactionFilters() error {
	var err error
	redactionFilters := viper.GetString(option.KeyRedactionFilters)
	fieldfilters.RedactionFilters, err = fieldfilters.ParseRedactionFilterList(redactionFilters)
	if err == nil {
		log.Info("Configured redaction filters", "redactionFilters", fieldfilters.RedactionFilters)
	} else {
		log.Error("Error configuring redaction filters", logfields.Error, err)
	}
	return err
}

// saveInitInfo writes daemon info read by tetra and bugtool, advertising the
// unix listener so in-pod tooling avoids the (possibly TLS-gated) TCP listener.
func saveInitInfo() error {
	addr := ""
	if sockPath, ok := resolveUnixSocketPath(option.Config.ServerAddress); ok {
		addr = "unix://" + sockPath
	}
	info := bugtool.InitInfo{
		ExportFname: option.Config.ExportFilename,
		LibDir:      option.Config.HubbleLib,
		BTFFname:    option.Config.BTF,
		MetricsAddr: option.Config.MetricsServer,
		ServerAddr:  addr,
		GopsAddr:    option.Config.GopsAddr,
		MapDir:      bpf.MapPrefixPath(),
		PID:         os.Getpid(),
	}

	if err := bugtool.SaveInitInfo(&info); err != nil {
		return err
	}

	if !enterpriseOption.Config.EnableApplicationModel {
		return nil
	}

	extraFiles := make(map[string]string)
	if enterpriseOption.Config.ApplicationModelExportFilename != "" {
		if p, err := filepath.Abs(enterpriseOption.Config.ApplicationModelExportFilename); err == nil {
			extraFiles["app_model_export.json"] = p
		} else {
			log.Warn("Failed to resolve export file path for bugtool", logfields.Error, err, "filename", enterpriseOption.Config.ApplicationModelExportFilename)
		}
	}
	if enterpriseOption.Config.TelemetryExportFilename != "" {
		if p, err := filepath.Abs(enterpriseOption.Config.TelemetryExportFilename); err == nil {
			extraFiles["telemetry_export.json"] = p
		} else {
			log.Warn("Failed to resolve export file path for bugtool", logfields.Error, err, "filename", enterpriseOption.Config.TelemetryExportFilename)
		}
	}
	if enterpriseOption.Config.ConnectionLogFileName != "" {
		if p, err := filepath.Abs(enterpriseOption.Config.ConnectionLogFileName); err == nil {
			extraFiles["connection_log.json"] = p
		} else {
			log.Warn("Failed to resolve export file path for bugtool", logfields.Error, err, "filename", enterpriseOption.Config.ConnectionLogFileName)
		}
	}
	if len(extraFiles) > 0 {
		return bugtool.SaveExtraFiles(extraFiles)
	}

	return nil
}

func stopProfile() {
	if option.Config.MemProfile != "" {
		log.Info("Stopping mem profiling", "file", option.Config.MemProfile)
		f, err := os.Create(option.Config.MemProfile)
		if err != nil {
			logger.Fatal(log, "Could not create memory profile", logfields.Error, err, "file", option.Config.MemProfile)
		}
		defer f.Close()
		// get up-to-date statistics
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			logger.Fatal(log, "Could not write memory profile", logfields.Error, err)
		}
	}
	if option.Config.CpuProfile != "" {
		log.Info("Stopping cpu profiling", "file", option.Config.CpuProfile)
		pprof.StopCPUProfile()
	}
}

func getOldBpfDir(path string) (string, error) {
	// bpffs directory will be removed, so we don't care
	if option.Config.ReleasePinned {
		return "", nil
	}
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	old := path + "_old"
	// remove the 'xxx_old' leftover instance if needed
	if _, err := os.Stat(old); err == nil {
		os.RemoveAll(old)
		log.Info("Found bpf leftover instance, removing", "path", old)
	}
	// rename current tetragon instance to tetragon_old
	if err := os.Rename(path, old); err != nil {
		return "", err
	}
	log.Info(fmt.Sprintf("Found bpf instance: %s, moved to: %s", path, old))
	return old, nil
}

func deleteOldBpfDir(path string) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		log.Error("Failed to remove old bpf instance", logfields.Error, err, "path", path)
		return
	}
	log.Info("Removed bpf instance: " + path)
}

func loadInitialSensor(ctx context.Context) error {
	mgr := observer.GetSensorManager()
	initialSensor := base.GetInitialSensor()
	if err := mgr.AddSensor(ctx, initialSensor.Name, initialSensor); err != nil {
		return err
	}
	return mgr.EnableSensor(ctx, initialSensor.Name)
}

func openGRPCPolicyStore() (*policystore.Store, error) {
	if !option.Config.PersistGRPCPolicies {
		return nil, nil
	}

	store, err := policystore.OpenAndLoad(option.Config.PersistGRPCPoliciesDir)
	if err != nil {
		return nil, fmt.Errorf("open persistent policy store %q: %w", option.Config.PersistGRPCPoliciesDir, err)
	}

	log.Info("Opened persistent policy store",
		"directory", option.Config.PersistGRPCPoliciesDir,
		"policies", len(store.List()))

	return store, nil
}

type persistedTracingPolicy struct {
	policy  tracingpolicy.TracingPolicy
	enabled bool
}

func restoreGRPCPolicies(ctx context.Context, store *policystore.Store, manager *sensors.Manager) error {
	if store == nil {
		return nil
	}

	// Validate all records before loading any of them. This avoids partially
	// restoring a store when a later record is malformed.
	records := store.List()
	log.Info("Starting persisted gRPC policy restoration",
		"policies", len(records))
	policies := make([]persistedTracingPolicy, 0, len(records))
	for _, entry := range records {
		policy, err := tracingpolicy.FromYAML(entry.Pol.YAML)
		if err != nil {
			return fmt.Errorf("restore persisted gRPC policy %s: parse YAML: %w", entry.ID.Name, err)
		}
		if policy.TpName() != entry.ID.Name || policy.TpNamespace() != entry.ID.Namespace {
			return fmt.Errorf(
				"restore persisted gRPC policy %s: record identity does not match YAML identity %s/%s",
				entry.ID.Name, policy.TpNamespace(), policy.TpName())
		}

		policies = append(policies, persistedTracingPolicy{
			policy: &server.GRPCTracingPolicy{
				TracingPolicy: policy,
				Domain:        entry.ID.Domain,
			},
			enabled: entry.Pol.Enabled,
		})
	}

	for i, persisted := range policies {
		policy := persisted.policy
		state := sensors.DisabledState
		if persisted.enabled {
			state = sensors.EnabledState
		}
		log.Info("Loading persisted gRPC policy",
			"name", policy.TpName(),
			"namespace", policy.TpNamespace(),
			"domain", policy.TpDomain(),
			"enabled", persisted.enabled)
		if err := manager.AddTracingPolicyWithState(ctx, policy, state); err != nil {
			// as we want all-or-nothing semantics a single policy load error has to
			// delete all previously loaded policies
			var rollbackErr error
			for j := i - 1; j >= 0; j-- {
				restored := policies[j].policy
				if err := manager.DeleteTracingPolicy(ctx, restored.TpName(), restored.TpNamespace(), restored.TpDomain()); err != nil {
					rollbackErr = errors.Join(rollbackErr, fmt.Errorf("roll back restored gRPC policy %s: %w", tracingpolicy.TpLongname(restored), err))
				}
			}
			return errors.Join(fmt.Errorf("restore persisted gRPC policy %s: load: %w", tracingpolicy.TpLongname(policy), err), rollbackErr)
		}
		log.Info("Restored persisted gRPC policy",
			"name", policy.TpName(),
			"namespace", policy.TpNamespace(),
			"domain", policy.TpDomain(),
			"enabled", persisted.enabled)
	}
	log.Info("Completed persisted gRPC policy restoration",
		"policies", len(policies))

	return nil
}

func tetragonExecuteCtx(ctx context.Context, cancel context.CancelFunc, ready func()) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		logger.Fatal(log, "Failed to setup logging", logfields.Error, err)
	}
	updateServiceStarting()

	if !filepath.IsAbs(option.Config.TracingPolicyDir) {
		logger.Fatal(log, fmt.Sprintf("Failed path specified by --tracing-policy-dir '%q' is not absolute", option.Config.TracingPolicyDir))
	}
	option.Config.TracingPolicyDir = filepath.Clean(option.Config.TracingPolicyDir)

	grpcPolicyStore, err := openGRPCPolicyStore()
	if err != nil {
		return err
	}

	if !filepath.IsAbs(enterpriseOption.Config.PoliciesDir) {
		logger.Fatal(log, fmt.Sprintf("Failed path specified by --policy-dir '%q' is not absolute", enterpriseOption.Config.PoliciesDir))
	}
	enterpriseOption.Config.PoliciesDir = filepath.Clean(enterpriseOption.Config.PoliciesDir)

	if option.Config.RBSize != 0 && option.Config.RBSizeTotal != 0 {
		logger.Fatal(log, "Can't specify --rb-size and --rb-size-total together")
	}

	log.Info("Starting Tetragon Enterprise", "version", version.Version)
	log.Info("config settings", "config", enterpriseOption.RedactedSettings())

	// Log early security context in case something fails
	logCurrentSecurityContext()

	// Create run dir early
	os.MkdirAll(defaults.DefaultRunDir, 0755)

	// When an instance terminates or restarts it may cleanup bpf programs,
	// having a check here to see if another instance is already running.
	pid, err := pidfile.Create()
	if err != nil {
		// pidfile.Create returns error if creation of pid file failed with error
		// other than pidfile.ErrPidFileAccess and pidfile.ErrPidIsNotAlive.
		// In most cases this will mean that another instance of Tetragon is up
		// and running and may interfere on eBPF programs and/or maps and lead
		// to unpredictable behavior.
		return fmt.Errorf("failed to create pid file '%s', another Tetragon instance seems to be up and running: %w", defaults.DefaultPidFile, err)
	}
	defer pidfile.Delete()

	log.Info("Tetragon pid file creation succeeded", "pid", pid, "pidfile", defaults.DefaultPidFile)

	if option.Config.KeepSensorsOnExit {
		// The effect of having both --release-pinned-bpf and --keep-sensors-on-exit options
		// enabled is that the previous bpffs instance will be removed early before the new
		// config is set. Not a big problem, but better to warn..
		if option.Config.ReleasePinned {
			log.Warn("Options --release-pinned-bpf and --keep-sensors-on-exit enabled together, we will remove bpffs instance early.")
		}
		log.Info("Not unloading sensors on exit")
	}

	if err := checkStructAlignments(); err != nil {
		return fmt.Errorf("struct alignment checks failed: %w", err)
	}

	// Initialize namespaces here. On errors fail, there is
	// no point to continue if read/ptrace on /proc/1/ fails.
	// Providing correct information can't be achieved anyway.
	err = initHostNamespaces()
	if err != nil {
		logger.Fatal(log, "Failed to initialize host namespaces", "procfs", option.Config.ProcFS, logfields.Error, err)
	}

	checkProcFS()

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountTraceFS()
	bpf.CheckOrMountCgroup2()

	if option.Config.PprofAddr != "" {
		go func() {
			log.Info("Starting pprof via HTTP on " + option.Config.PprofAddr)
			if err := servePprof(option.Config.PprofAddr); err != nil {
				log.Warn("Failed serving pprof via HTTP", logfields.Error, err)
			}
		}()
	}

	// Start profilers first as we have to capture them in signal handling
	if option.Config.MemProfile != "" {
		log.Info("Starting mem profiling", "file", option.Config.MemProfile)
	}

	if option.Config.CpuProfile != "" {
		f, err := os.Create(option.Config.CpuProfile)
		if err != nil {
			logger.Fatal(log, "Could not create CPU profile", logfields.Error, err, "file", option.Config.CpuProfile)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			logger.Fatal(log, "Could not start CPU profile", logfields.Error, err)
		}
		log.Info("Starting cpu profiling", "file", option.Config.CpuProfile)
	}

	defer stopProfile()

	// We try to detect previous instance, which might be there for legitimate
	// reasons (--keep-sensors-on-exit) and rename to 'tetragon_old'.
	// Then we do the 'best' effort to keep running sensors as long as possible
	// and remove 'tetragon_old' directory when tetragon is started and its
	// policy is loaded.
	// If there's --release-pinned-bpf option enabled, we need to remove previous
	// sysfs instance right away (see check for option.Config.ReleasePinned below),
	// so we don't bother renaming in that case.
	oldBpfDir, err := getOldBpfDir(bpf.MapPrefixPath())
	if err != nil {
		return fmt.Errorf("failed to move old tetragon base directory: %w", err)
	}

	// Raise memory resource
	bpf.ConfigureResourceLimits()
	updateServiceStarting()

	// Get observer bpf maps and programs directory
	observerDir := getObserverDir()
	option.Config.BpfDir = observerDir

	// Check if option to remove old BPF and maps is enabled.
	if option.Config.ReleasePinned {
		// Always release tg_ prefix as we are relatively sure these belong to us
		// but, do more aggressive detach op to clean up old versioned programs when
		// told.
		if err := detachTetragonCgroups(true, enterpriseOption.Config.DetachOldBpf); err != nil {
			log.Warn("Failed to detach cgroups, Consider removing it manually", logfields.Error, err)
		} else {
			log.Info("Successfully released attched cgroups.")
		}
		if err := os.RemoveAll(observerDir); err != nil {
			log.Warn("Failed to release pinned BPF programs and map, Consider removing it manually", logfields.Error, err, "bpf-dir", observerDir)
		} else {
			log.Info("Successfully released pinned BPF programs and maps", "bpf-dir", observerDir)
		}
	}

	// Get observer from configFile
	obs := observer.NewObserver()
	defer func() {
		terminateFsScanner()
		obs.PrintStats()
	}()

	go func() {
		s := <-sigs
		// if we receive a signal, call cancel so that contexts are finalized, which will
		// leads to normally return from tetragonExecute().
		log.Info(fmt.Sprintf("Received signal %s, shutting down...", s))
		cancel()
	}()

	if err := obs.InitSensorManager(); err != nil {
		return fmt.Errorf("failed to start sensor manager: %w", err)
	}

	err = initCachedBTF(option.Config.HubbleLib, option.Config.BTF)
	if err != nil {
		return fmt.Errorf("failed to init cached BTF: %w", err)
	}

	// needs BTF, so caling it after InitCachedBTF
	log.Info("BPF detected features: " + bpf.LogFeatures())

	if err := observer.InitDataCache(option.Config.DataCacheSize); err != nil {
		return err
	}
	updateServiceStarting()

	if option.Config.MetricsServer != "" {
		go metricsconfig.EnableMetrics(option.Config.MetricsServer)
		enterpriseMetricsConfig.InitAllHealthMetrics(metricsconfig.GetRegistry())

		if option.Config.EnableEventMetrics {
			enterpriseMetricsConfig.InitAllEventMetrics(metricsconfig.GetRegistry())

		}

		initK8sMetrics()
	}

	if enterpriseOption.Config.EnableAWSSonar {
		if enterpriseOption.Config.AWSSonarRegion == "" {
			log.Info("AWS Sonar enabled, but region not set, skipping. To publish metrics to Sonar, set aws-sonar-region.")
		} else {
			// TODO: Create a TCP policy for Sonar automatically.
			go layer3.InitSonar(ctx)
		}
	}

	// Probe runtime configuration and do not fail on errors
	obs.UpdateRuntimeConf(option.Config.BpfDir)

	// Must happen before any export writer is created, so that they can tee to it.
	if err := splunkHec.Init(ctx); err != nil {
		return err
	}
	if enterpriseOption.Config.SplunkHECEndpoint != nil {
		log.Info("Exporting JSON records to the Splunk HTTP Event Collector",
			"endpoint", enterpriseOption.Config.SplunkHECEndpoint.String(),
			"sourcetypes", enterpriseOption.Config.SplunkHECSourcetypes)
	}

	// Initialize alert rule manager
	alertsManager := alerts.NewRuleManager()

	// Initialize a pod accessor used to retrieve process metadata. This should
	// happen before the sensors are loaded, otherwise events will be stuck
	// waiting for metadata.
	podAccessor := k8sPodAccessor()
	// Gate file and gRPC policies by spec.nodeSelector against a startup
	// snapshot of the host labels, regardless of k8s mode (in k8s the
	// crdwatcher additionally gates CRD policies against the Node object and
	// reconciles on label updates).
	var nodeSelectorLabels map[string]string
	nodeMetadata, err := local.GetMetadataService()
	if err != nil {
		log.Warn("Failed to get node info. node_labels field will be empty", logfields.Error, err)
	} else {
		labels, err := nodeMetadata.GetLabels(ctx)
		if err != nil {
			log.Warn("Failed to get node info. node_labels field will be empty", logfields.Error, err)
		} else {
			node.SetNodeLabels(labels)
			nodeSelectorLabels = labels
		}

		// Register node for non-k8s environments
		registerer, err := register.NewNodeRegisterer(nodeMetadata)
		if err != nil {
			log.Warn("Failed to get node registration service", logfields.Error, err)
		} else {
			if err := registerer.Register(ctx); err != nil {
				log.Warn("Failed to register node", logfields.Error, err)
			}
		}
	}

	err = initCilumState(ctx)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}

	pcGCInterval := option.Config.ProcessCacheGCInterval
	if pcGCInterval <= 0 {
		pcGCInterval = defaults.DefaultProcessCacheGCInterval
	}

	if option.Config.DisableProcessCache {
		log.Info("Process cache is disabled")
		process.SetK8sWatcher(podAccessor)
	} else {
		if err := process.InitCache(podAccessor, option.Config.ProcessCacheSize, pcGCInterval); err != nil {
			return fmt.Errorf("failed to init process cache: %w", err)
		}
	}

	// cleanupWg is needed to ensure that gRPC code cleanly finishes before we exit (e.g,
	// due to a signal). This is needed, for example, so that the exported writes full
	// (uncorrupted) to the file. See: 4b7c8d1c427a46b864763e910e8f3511e1c4eb00.
	var cleanupWg sync.WaitGroup
	defer cleanupWg.Wait()

	// The "defer cleanupWg.Wait()" above, might introduce deadlocks if an error happens.
	// This is because cancel() will not be called until cleanupWg.Wait() returns.
	// But, the code in server/server.go:GetEventsWG() will only call cleanupWg.Done() if ctx.Done()
	// Which causes a deadlock. To fix this, we add a new ctx and we pass that to the rest of the
	// initialization functions. This means that we can cancel them without causing a deadlock
	// using cancel2.
	ctx, cancel2 := context.WithCancel(ctx)
	defer cancel2()

	hookRunner := rthooks.GlobalRunner().WithWatcher(podAccessor)
	updateServiceStarting()

	err = setRedactionFilters()
	if err != nil {
		return err
	}

	modelServer, err := getDefaultNewServer()
	if err != nil {
		return err
	}

	// Load initial sensor before we start the server,
	// so it's there before we allow to load policies.
	if err = loadInitialSensor(ctx); err != nil {
		return err
	}
	if enterpriseOption.Config.EnableApplicationModel {
		if err = loadInitialProcFsSensor(ctx); err != nil {
			return err
		}
	}
	if err = loadFIMInitialSensor(ctx); err != nil {
		return err
	}
	if err = restoreGRPCPolicies(ctx, grpcPolicyStore, observer.GetSensorManager()); err != nil {
		observer.RemoveSensors(ctx)
		if oldBpfDir != "" {
			// If we failed to restore policies, here we have already renamed the tetragon bpf directory
			// to tetragon_old. On the next try, we will also remove tetragon_old and we will miss any
			// persistent policies that we may had. To avoid that, in the case of failed policy restore,
			// we rename back tetragon_old to tetragon.
			if removeErr := os.RemoveAll(observerDir); removeErr != nil {
				return errors.Join(err, fmt.Errorf("failed to remove bpf progs %s: %w", observerDir, removeErr))
			}
			if renameErr := os.Rename(oldBpfDir, observerDir); renameErr != nil {
				return errors.Join(err, fmt.Errorf("failed to restore previous bpf progs from %s to %s: %w", oldBpfDir, observerDir, renameErr))
			}
			log.Info("Restored previous bpf progs", "from", oldBpfDir, "to", observerDir)
		}
		return err
	}
	defer func() {
		observer.RemoveSensors(ctx)
	}()
	observer.GetSensorManager().LogSensorsAndProbes(ctx)

	// now that the base sensor is loaded, we can start the mandate goroutine
	var mandateMgr mandate.Manager
	mandateConf := enterpriseOption.Config.MandateConf
	if mandateConf.URL != "" {
		var alMgr alerts.RuleManager
		if enterpriseOption.Config.EnableAlerts {
			alMgr = alertsManager
		}
		var err error
		mandateMgr, err = mandate.NewManager(mandateConf, observer.GetSensorManager(), alMgr)
		if err != nil {
			return err
		}
		if err = mandateMgr.Start(); err != nil {
			return err
		}
	}

	pm, err := fgsGrpc.NewProcessManager(
		ctx,
		&cleanupWg,
		observer.GetSensorManager(),
		hookRunner,
		grpcPolicyStore)
	if err != nil {
		return fmt.Errorf("failed to create process manager: %w", err)
	}
	alerter := alerts.NewAlerter(ctx, alertsManager)
	netpolManager := netpol.New(ctx)

	// Fetch the exporter if needed
	var exporter *exporter.Exporter
	if option.Config.ExportFilename != "" {
		exporter, err = getExporter(ctx, pm.Server)
		if err != nil {
			return fmt.Errorf("failed to create a new exporter: %w", err)
		}
	}

	// Start gRPC server. Gate AddTracingPolicy by spec.nodeSelector against
	// the host labels, like the file loader (the server is left unwrapped when
	// no host labels were resolved).
	fgsServer := eeserver.NewFilterServer(pm.Server, observer.GetSensorManager(), log, nodeSelectorLabels)
	if err = Serve(ctx, option.Config.ServerAddress, fgsServer, modelServer, mandatesrv.New(mandateMgr), alerter, netpolManager, rule.New(alertsManager, observer.GetSensorManager()), eventlog.New(exporter, alertsManager)); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Finally start exporter if needed
	if exporter != nil {
		if err = exporter.Start(); err != nil {
			return fmt.Errorf("failed to start json exporter: %w", err)
		}
	}

	if enterpriseOption.Config.EnableAlerts {
		if err = alerter.Start(pm.Server); err != nil {
			return fmt.Errorf("failed to start alerting: %w", err)
		}
		log.Info("Started alerting.")
	}

	if option.Config.HealthServerAddress != "" {
		_ = health.StartHealthServer(ctx, option.Config.HealthServerAddress, option.Config.HealthServerInterval)
	}

	obs.AddListener(pm)
	saveInitInfo()
	updateServiceStarting()

	err = initK8s(alertsManager)
	if err != nil {
		return err
	}

	obs.LogPinnedBpf(observerDir)

	if err = procevents.GetRunningProcs(); err != nil {
		return err
	}
	if err = startLayer3Progs(ctx); err != nil {
		return err
	}
	if err = startNetworkInterfaceStats(ctx); err != nil {
		return err
	}

	if err = startSockopsSensor(ctx); err != nil {
		return err
	}

	if err = startSockmapSensor(ctx); err != nil {
		return err
	}

	if err = startNopSensor(ctx); err != nil {
		return err
	}

	if err = startHttpSensor(ctx); err != nil {
		return err
	}

	// Start the application model exporter after layer3 progs so that all BPF
	// maps (including tg_cgid_wlid, pinned by the layer3 sensor) are available
	// when the exporter first calls GetProcessModel.
	if enterpriseOption.Config.ApplicationModelExportInterval != 0 {
		if err = startApplicationModelExporter(ctx, modelServer); err != nil {
			return fmt.Errorf("failed to start json application model exporter: %w", err)
		}
	}

	// We need to the execve map to be pre-populated via procevents, so make
	// sure to let that run first. TODO: eventually we may be able to use a
	// similar technique to completely remove procevents, but this will require
	// some OSS work.
	if enterpriseOption.Config.EnableApplicationModel {
		if err = procFSWalk(); err != nil {
			logger.GetLogger().Warn("failed to pre-populate application model entries", logfields.Error, err)
		}
	}

	if err := cgrouprate.NewCgroupRate(ctx, pm, &option.Config.CgroupRate); err != nil {
		return err
	}
	cgrouprate.Config()

	// start the process cache cleaner
	if enterpriseOption.Config.ProcessCacheStaleInterval.Nanoseconds() <= 0 {
		return fmt.Errorf("process-cache-state-interval must be > 0")
	}
	processcacheclean.Start()
	defer processcacheclean.Stop()

	if err = policies.LoadFromConfig(ctx, alertsManager, log, nodeSelectorLabels); err != nil {
		return err
	}

	// Remove previous tetragon instance if detected
	deleteOldBpfDir(oldBpfDir)

	// k8s should have metrics, so periodically log only in a non k8s
	if !enterpriseOption.K8SControlPlaneEnabled() {
		go logStatus(ctx, obs)
	}

	// Start even if BPFDebugAreas is empty;
	// BPF probe might've been compiled with TETRAGON_BPF_DEBUG
	// thus all bpf_trace_printk() are forcefully enabled.
	if option.Config.BPFDebugLog {
		go logBPFDebug(ctx)
	}

	updateServiceStarting()

	powershell.StartPowershellEvtSubscriber()

	// Wrap the caller's ready callback so the health package also reports the
	// agent as fully initialized once startup completes.
	wrappedReady := func() {
		ready()
		health.SetReady()
	}

	return obs.StartReady(ctx, wrappedReady)
}

// Periodically log current status every 24 hours. For lost or error
// events we ratelimit statistics to 1 message per every 1hour and
// only if they increase, to inform users that events are being lost.
func logStatus(ctx context.Context, obs *observer.Observer) {
	prevLost := uint64(0)
	prevErrors := uint64(0)
	lostTicker := time.NewTicker(1 * time.Hour)
	defer lostTicker.Stop()
	logTicker := time.NewTicker(24 * time.Hour)
	defer logTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-logTicker.C:
			// We always print stats
			obs.PrintStats()
			// Update lost and errors
			prevLost = obs.ReadLostEvents()
			prevErrors = obs.ReadErrorEvents()
		case <-lostTicker.C:
			lost := obs.ReadLostEvents()
			errors := obs.ReadErrorEvents()
			if lost > prevLost || errors > prevErrors {
				obs.PrintStats()
				prevLost = lost
				prevErrors = errors
			}
		}
	}
}

func logBPFDebug(ctx context.Context) {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Warn("failed to open /sys/kernel/debug/tracing/trace_pipe", "err", err)
		return
	}
	defer f.Close()

	buf := make([]byte, 4096)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := f.Read(buf)
		if n > 0 {
			lines := strings.SplitSeq(string(buf[:n]), "\n")
			for line := range lines {
				// Only print tetragon messages
				i := strings.Index(line, "tetragon")
				if i != -1 {
					// Drop all stuff before tetragon prefix
					logger.GetLogger().Info(line[i:])
				} else if strings.Contains(line, "LOST") {
					// Print LOST messages, eg:
					// CPU:12 [LOST 711 EVENTS]
					// CPU:3 [LOST 3698 EVENTS]
					// CPU:1 [LOST 8509 EVENTS]
					logger.GetLogger().Info(line)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
		}
	}
}

// getObserverDir returns the path to the observer directory based on the BPF
// map root. This function relies on the map root to be set properly via
// github.com/cilium/tetragon/pkg/bpf.CheckOrMountFS().
func getObserverDir() string {
	return bpf.MapPrefixPath()
}

// exportWriter is a rotating export file that also tees every JSON record it
// receives to the Splunk HTTP Event Collector.
type exportWriter struct {
	*lumberjack.Logger
	hec io.Writer
}

func (w *exportWriter) Write(p []byte) (int, error) {
	n, err := w.Logger.Write(p)
	if n > 0 {
		// Shipping to Splunk is best effort and must not fail the file write.
		w.hec.Write(p[:n])
	}
	return n, err
}

// getWriter returns lumberjack logger and the absolute path to the file.
func getWriter(filename string, maxSizeMB int, maxBackups int, compress bool, sourcetype string) (*exportWriter, error) {
	writer := &lumberjack.Logger{
		Filename:   filename,
		MaxSize:    maxSizeMB,
		MaxBackups: maxBackups,
		Compress:   compress,
	}

	perms, err := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
	if err != nil {
		log.Warn(fmt.Sprintf("Failed to parse export file permission '%s', failing back to %v",
			option.KeyExportFilePerm, perms), "filename", filename)
	}
	writer.FileMode = perms

	finfo, err := os.Stat(filepath.Clean(writer.Filename))
	if err == nil && finfo.IsDir() {
		// Error if exportFilename points to a directory
		return nil, fmt.Errorf("passed export JSON logs file (%s) point to a directory", filename)
	}
	abspath, err := filepath.Abs(filepath.Clean(writer.Filename))
	if err != nil {
		log.Warn("Failed to get absolute path of export file", logfields.Error, err, "filename", writer.Filename)
	} else {
		log.Info("Initialized export file", "filename", abspath)
	}
	return &exportWriter{Logger: writer, hec: splunkHec.Writer(sourcetype, filename)}, nil
}

func getExporter(ctx context.Context, server *server.Server) (*exporter.Exporter, error) {
	allowList, denyList, err := getExportFilters()
	if err != nil {
		return nil, err
	}
	fieldFilters, err := getFieldFilters()
	if err != nil {
		return nil, err
	}
	writer, err := getWriter(option.Config.ExportFilename, option.Config.ExportFileMaxSizeMB, option.Config.ExportFileMaxBackups, option.Config.ExportFileCompress, enterpriseOption.SplunkHECSourcetypeEvents)
	if err != nil {
		return nil, err
	}
	var flowWriter *exportWriter
	enableFlowExport := enterpriseOption.Config.FlowExportFilename != ""
	if enableFlowExport {
		flowWriter, err = getWriter(enterpriseOption.Config.FlowExportFilename, enterpriseOption.Config.FlowExportFileMaxSizeMB, enterpriseOption.Config.FlowExportFileMaxBackups, enterpriseOption.Config.FlowExportFileCompress, enterpriseOption.SplunkHECSourcetypeFlows)
		if err != nil {
			return nil, err
		}
	}

	var ocsfWriter *exportWriter
	enableOCSFClient := enterpriseOption.Config.OCSFExportServer != ""
	enableOCSFExport := enterpriseOption.Config.OCSFExportFilename != ""
	if enableOCSFExport {
		ocsfWriter, err = getWriter(enterpriseOption.Config.OCSFExportFilename, enterpriseOption.Config.OCSFExportFileMaxSizeMB, enterpriseOption.Config.OCSFExportFileMaxBackups, enterpriseOption.Config.OCSFExportFileCompress, enterpriseOption.SplunkHECSourcetypeOCSF)
		if err != nil {
			return nil, err
		}
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return nil, fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.Info("Periodically rotating JSON export files", "frequency", option.Config.ExportFileRotationInterval.String())
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.Warn("Failed to rotate JSON export file", logfields.Error, rotationErr, "file", option.Config.ExportFilename)
					}
					if flowWriter != nil {
						log.Info("Rotating JSON flow export file", "file", enterpriseOption.Config.FlowExportFilename)
						if rotationErr := flowWriter.Rotate(); rotationErr != nil {
							log.Warn("Failed to rotate JSON flow export file", logfields.Error, rotationErr, "file", enterpriseOption.Config.FlowExportFilename)
						}
					}
				}
			}
		}()
	}

	nodeIPs := encoder.GetNodeIPs()
	// Track how many bytes are written to the event export location
	encoderWriter := exporter.NewExportedBytesTotalWriter(writer)
	encoder := encoder.NewJSONEncoder(encoderWriter, ocsfWriter, flowWriter, enterpriseOption.Config.OCSFExportServer, enableOCSFExport, enableOCSFClient, enableFlowExport, nodeIPs)
	var rateLimiter *ratelimit.RateLimiter
	if option.Config.ExportRateLimit >= 0 {
		rateLimiter = ratelimit.NewRateLimiter(ctx, 1*time.Minute, option.Config.ExportRateLimit, encoder)
	}
	var aggregationOptions *tetragon.AggregationOptions
	if option.Config.EnableExportAggregation {
		aggregationOptions = &tetragon.AggregationOptions{
			WindowSize:        durationpb.New(option.Config.ExportAggregationWindowSize),
			ChannelBufferSize: option.Config.ExportAggregationBufferSize,
		}
	}
	req := tetragon.GetEventsRequest{AllowList: allowList, DenyList: denyList, AggregationOptions: aggregationOptions, FieldFilters: fieldFilters}
	log.Info("Configured field filters", "fieldFilters", fieldFilters)
	log.Info("Starting JSON exporter", "logger", writer)
	return exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
}

func registerSplunkServiceServer(s *grpc.Server) {
	splunkV1.RegisterSplunkServiceServer(s, splunkHec.NewSplunkService())
}

func Serve(
	ctx context.Context, listenAddr string,
	srv tetragon.FineGuidanceSensorsServer, model *model.Server, mandate *mandatesrv.Server, alerter tetragon.AlertServiceServer, netpol *netpol.NetworkPolicyManager, rule *rule.Server, eventlogSrv *eventlog.Server,
	extraOpts ...grpc.ServerOption) error {
	if listenAddr == "" {
		return nil
	}
	register := func(s *grpc.Server) {
		tetragon.RegisterFineGuidanceSensorsServer(s, srv)
		tetragon.RegisterMandateServiceServer(s, mandate)
		tetragon.RegisterAlertServiceServer(s, alerter)
		tetragon.RegisterRuleServiceServer(s, rule)
		tetragon.RegisterNetworkPolicyServiceServer(s, netpol)
		tetragon.RegisterEventLogServiceServer(s, eventlogSrv)
		registerSplunkServiceServer(s)

		if model != nil {
			registerApplicationModelServiceServer(s, model)
			registerProcessModelServiceServer(s, model)
		}
	}
	proto, addr, err := server.SplitListenAddr(listenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse listen address: %w", err)
	}

	if proto == "unix" {
		if err := serveOne(ctx, "unix", addr, extraOpts, register); err != nil {
			return fmt.Errorf("starting unix gRPC listener: %w", err)
		}
		return nil
	}

	if sockPath, ok := resolveUnixSocketPath(listenAddr); ok {
		if err := serveOne(ctx, "unix", sockPath, extraOpts, register); err != nil {
			return fmt.Errorf("starting unix gRPC listener: %w", err)
		}
	}

	tlsOpts, tlsEnabled, err := buildServerTLSOptions(ctx)
	if err != nil {
		return err
	}
	if !tlsEnabled {
		log.Warn("Tetragon gRPC TCP listener is exposing the API without TLS; configure --"+
			option.KeyServerTLSCertFile+" and --"+
			option.KeyServerTLSKeyFile+" to enable it",
			"address", addr)
	}
	grpcOpts := append([]grpc.ServerOption{}, extraOpts...)
	grpcOpts = append(grpcOpts, tlsOpts...)
	if err := serveOne(ctx, proto, addr, grpcOpts, register); err != nil {
		return fmt.Errorf("starting TCP gRPC listener: %w", err)
	}
	return nil
}

// serveOne binds a listener synchronously (so bind errors are returned to the
// caller) and serves it in the background until ctx is canceled.
func serveOne(
	ctx context.Context,
	proto, addr string,
	grpcOpts []grpc.ServerOption,
	register func(*grpc.Server),
) error {
	var listener net.Listener
	var err error
	if proto == "unix" {
		listener, err = unixlisten.ListenWithRename(addr, 0660)
	} else {
		listener, err = net.Listen(proto, addr)
	}
	if err != nil {
		return fmt.Errorf("listen %s://%s: %w", proto, addr, err)
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	register(grpcServer)

	go func() {
		log.Info("Starting gRPC server", "protocol", proto, "address", addr)
		if err := grpcServer.Serve(listener); err != nil {
			log.Error("gRPC Serve returned", logfields.Error, err)
		}
	}()
	go func() {
		<-ctx.Done()
		grpcServer.Stop()
		// if proto is unix, ListenWithRename() creates the socket
		// then renames it, so explicitly clean it up.
		if proto == "unix" {
			os.Remove(addr)
		}
	}()
	return nil
}

// buildServerTLSOptions returns grpc.Creds for the TCP listener, or nil when
// TLS is disabled. The boolean reports whether TLS is active.
func buildServerTLSOptions(ctx context.Context) ([]grpc.ServerOption, bool, error) {
	cfg := certloader.Config{
		CertFile:          option.Config.ServerTLSCertFile,
		KeyFile:           option.Config.ServerTLSKeyFile,
		ClientCAFiles:     option.Config.ServerTLSClientCAFiles,
		RequireClientCert: option.Config.ServerTLSRequireClientCert,
	}
	if !cfg.Enabled() {
		return nil, false, nil
	}
	// Lazy load: cert material may be provisioned after startup; Watch
	// promotes the reloader to ready once the files appear.
	reloader, err := certloader.NewReloaderLazy(cfg)
	if err != nil {
		return nil, false, fmt.Errorf("preparing gRPC TLS: %w", err)
	}
	certloader.Watch(ctx, reloader)
	log.Info("gRPC TLS enabled",
		"mtls", cfg.RequireClientCert,
		"cert", cfg.CertFile,
		"key", cfg.KeyFile,
		"client-ca-files", len(cfg.ClientCAFiles),
		"ready", reloader.Ready(),
	)
	if !reloader.Ready() {
		log.Warn("gRPC TLS material not yet on disk; handshakes will fail until files appear at the configured paths",
			"cert", cfg.CertFile,
			"key", cfg.KeyFile,
		)
	}
	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(reloader.ServerConfig()))}, true, nil
}

func startGopsServer() error {
	// Empty means no gops
	if option.Config.GopsAddr == "" {
		return nil
	}

	if err := gops.Listen(gops.Options{
		Addr:                   option.Config.GopsAddr,
		ReuseSocketAddrAndPort: true,
	}); err != nil {
		return err
	}

	log.Info("Starting gops server", "addr", option.Config.GopsAddr)

	return nil
}

func servePprof(addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprofhttp.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprofhttp.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprofhttp.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprofhttp.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprofhttp.Trace)
	return http.ListenAndServe(addr, mux)
}

func resizeCaches() error {
	dns.ResizeCache(enterpriseOption.Config.DnsCacheSize)
	return nscache.ResizeCache(enterpriseOption.Config.NetNsCacheSize)
}

func Execute() error {
	rootCmd := &cobra.Command{
		Use:   "tetragon",
		Short: "Tetragon Enterprise - eBPF-based Security Observability and Runtime Enforcement",
		PreRun: func(_ *cobra.Command, _ []string) {
			if len(os.Args) > 0 {
				if path.Base(os.Args[0]) == "hubble-fgs" {
					logger.GetLogger().Warn("The name 'hubble-fgs' has been deprecated and is going away, please use 'tetragon' instead.")
				}
			}
		},
		Run: func(cmd *cobra.Command, _ []string) {
			if viper.GetBool(option.KeyGenerateDocs) {
				if err := doc.GenYaml(cmd, os.Stdout); err != nil {
					logger.Fatal(log, "Failed to generate docs", logfields.Error, err)
				}
				return
			}
			if err := option.ReadAndSetFlags(); err != nil {
				logger.Fatal(log, "Failed to parse command line flags", logfields.Error, err)
			}

			err := enterpriseOption.ReadAndValidateEnterpriseFlags()
			if err != nil {
				logger.Fatal(log, "Failed to read and validate flags", logfields.Error, err)
			}

			// Unfortunately, due to an over-reliance on init() throughout the codebase,
			// we have to rely on resizing the caches here rather than simply initializing
			// them. (Otherwise we'd require a bunch of refactors and NewCache calls in
			// a lot of different places.) This should be fine to do as the operation
			// shouldn't be prohibitively expensive and the caches won't actually have any
			// entries yet.
			if err := resizeCaches(); err != nil {
				logger.Fatal(log, "Failed to configure caches", logfields.Error, err)
			}

			if err := startGopsServer(); err != nil {
				logger.Fatal(log, "Failed to start gops server", logfields.Error, err)
			}

			if err := hubbleFGSExecute(); err != nil {
				logger.Fatal(log, "Failed to start tetragon", logfields.Error, err)
			}
		},
	}

	cobra.OnInitialize(func() {
		newEnv, err := validateEnv()
		if err != nil {
			// Warn about errors but do not fail, we will default to old
			// FGS_ environment to not break users.
			log.Warn("Failed to validate environment variables, using old 'FGS_' environment vars", logfields.Error, err)
		}
		newConf, err := validateConfig()
		if err != nil {
			logger.Fatal(log, "Failed to validate configuration", logfields.Error, err)
		}
		if newConf {
			readConfigSettings(newEnv, newConf, adminTgConfDir, adminTgConfDropIn, packageTgConfDropIns)
		} else {
			// Warn users about using old configuration directories /etc/hubble-fgs/
			log.Warn(fmt.Sprintf("Configuration directory '%s' has been deprecated, please use '%s' instead or --%s flag",
				oldAdminFgsConfDir, adminTgConfDir, option.KeyConfigDir))
			readConfigSettings(newEnv, newConf, oldAdminFgsConfDir, oldAdminFgsConfDropIn, packageTgConfDropIns)
		}
	})

	flags := rootCmd.PersistentFlags()

	option.AddFlags(flags)
	enterpriseOption.FixUpOSSFlags(flags)
	enterpriseOption.AddOSSpecificFlags(flags)
	enterpriseOption.AddEnterpriseFlags(flags)

	viper.BindPFlags(flags)
	return rootCmd.Execute()
}
