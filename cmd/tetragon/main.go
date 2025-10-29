package tetragon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	pprofhttp "net/http/pprof"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/tetragon/pkg/cgrouprate"
	"github.com/cilium/tetragon/pkg/fieldfilters"
	"github.com/cilium/tetragon/pkg/health"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/rthooks"

	"github.com/isovalent/hubble-fgs/pkg/policies"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/manager"
	"github.com/isovalent/hubble-fgs/pkg/mandate"
	mandatesrv "github.com/isovalent/hubble-fgs/pkg/mandate/server"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/netpol"
	register "github.com/isovalent/hubble-fgs/pkg/node"
	"github.com/isovalent/hubble-fgs/pkg/node/local"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	processcacheclean "github.com/isovalent/hubble-fgs/pkg/process"
	enterpriseWatcher "github.com/isovalent/hubble-fgs/pkg/watcher"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/pidfile"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tgsyscall"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crdwatcher"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
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

func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: option.Config.ExportFilename,
		LibDir:      option.Config.HubbleLib,
		BTFFname:    option.Config.BTF,
		MetricsAddr: option.Config.MetricsServer,
		ServerAddr:  option.Config.ServerAddress,
		GopsAddr:    option.Config.GopsAddr,
		MapDir:      bpf.MapPrefixPath(),
		PID:         os.Getpid(),
	}
	return bugtool.SaveInitInfo(&info)
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

func hubbleFGSExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return tetragonExecuteCtx(ctx, cancel, func() {})
}

func tetragonExecuteCtx(ctx context.Context, cancel context.CancelFunc, ready func()) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, tgsyscall.SIGRTMIN_20,
		tgsyscall.SIGRTMIN_21, tgsyscall.SIGRTMIN_22)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		logger.Fatal(log, "Failed to setup logging", logfields.Error, err)
	}

	if !filepath.IsAbs(option.Config.TracingPolicyDir) {
		logger.Fatal(log, fmt.Sprintf("Failed path specified by --tracing-policy-dir '%q' is not absolute", option.Config.TracingPolicyDir))
	}
	option.Config.TracingPolicyDir = filepath.Clean(option.Config.TracingPolicyDir)

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

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
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

	defaultLevel := logger.GetLogLevel(logger.GetLogger())
	go func() {
		for {
			s := <-sigs
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				// if we receive a signal, call cancel so that contexts are finalized, which will
				// leads to normally return from tetragonExecute().
				log.Info(fmt.Sprintf("Received signal %s, shutting down...", s))
				cancel()
				return
			case tgsyscall.SIGRTMIN_20: // SIGRTMIN+20
				currentLevel := logger.GetLogLevel(logger.GetLogger())
				if currentLevel == slog.LevelDebug {
					log.Info(fmt.Sprintf("Received signal SIGRTMIN+20: LogLevel is already '%s'", currentLevel))
				} else {
					logger.SetLogLevel(slog.LevelDebug)
					log.Info(fmt.Sprintf("Received signal SIGRTMIN+20: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel(logger.GetLogger())))
				}
			case tgsyscall.SIGRTMIN_21: // SIGRTMIN+21
				currentLevel := logger.GetLogLevel(logger.GetLogger())
				if currentLevel == slog.LevelDebug {
					log.Info(fmt.Sprintf("Received signal SIGRTMIN+21: LogLevel is already '%s'", currentLevel))
				} else {
					logger.SetLogLevel(slog.LevelDebug)
					log.Info(fmt.Sprintf("Received signal SIGRTMIN+21: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel(logger.GetLogger())))
				}
			case tgsyscall.SIGRTMIN_22: // SIGRTMIN+22
				logger.SetLogLevel(defaultLevel)
				log.Info(fmt.Sprintf("Received signal SIGRTMIN+22: resetting original LogLevel '%s'", logger.GetLogLevel(logger.GetLogger())))
			}
		}
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

	if option.Config.MetricsServer != "" {
		go metricsconfig.EnableMetrics(option.Config.MetricsServer)
		enterpriseMetricsConfig.InitAllMetrics(metricsconfig.GetRegistry())
		go enterpriseMetrics.StartPodDeleteHandler()
		// Handler must be registered before the watcher is started
		metrics.RegisterPodDeleteHandler()
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

	// Initialize alert rule manager
	alertsManager := alerts.NewRuleManager()

	// Initialize a pod accessor used to retrieve process metadata. This should
	// happen before the sensors are loaded, otherwise events will be stuck
	// waiting for metadata.
	var podAccessor watcher.PodAccessor
	// Start Kubernetes manager. Note this doesn't have to be in the if block
	// below. If Kubernetes is not enabled, this call returns a fake manager.
	kubernetesManager := manager.Get()
	if enterpriseOption.K8SControlPlaneEnabled() && enterpriseOption.InClusterControlPlaneEnabled() {
		log.Info("Enabling Kubernetes API")
		podAccessor = kubernetesManager.GetControllerManager()
	} else {
		log.Info("Disabling Kubernetes API")
		podAccessor = watcher.NewFakeK8sWatcher(nil)
	}
	nodeMetadata, err := local.GetMetadataService()
	if err != nil {
		log.Warn("Failed to get node info. node_labels field will be empty", logfields.Error, err)
	} else {
		labels, err := nodeMetadata.GetLabels(ctx)
		if err != nil {
			log.Warn("Failed to get node info. node_labels field will be empty", logfields.Error, err)
		} else {
			node.SetNodeLabels(labels)
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

	_, err = cilium.InitCiliumState(ctx, enterpriseOption.Config.EnableCilium)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}

	pcGCInterval := option.Config.ProcessCacheGCInterval
	if pcGCInterval <= 0 {
		pcGCInterval = defaults.DefaultProcessCacheGCInterval
	}

	if err := process.InitCache(podAccessor, option.Config.ProcessCacheSize, pcGCInterval); err != nil {
		return fmt.Errorf("failed to init process cache: %w", err)
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
	observer.GetSensorManager().LogSensorsAndProbes(ctx)
	defer func() {
		observer.RemoveSensors(ctx)
	}()

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
		hookRunner)
	if err != nil {
		return fmt.Errorf("failed to create process manager: %w", err)
	}
	alerter := alerts.NewAlerter(ctx, alertsManager)
	netpolManager := netpol.New(ctx)

	// Start gRPC server
	if err = Serve(ctx, option.Config.ServerAddress, pm.Server, modelServer, mandatesrv.New(mandateMgr), alerter, netpolManager); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Start data exporters
	if option.Config.ExportFilename != "" {
		if err = startExporter(ctx, pm.Server); err != nil {
			return fmt.Errorf("failed to start json exporter: %w", err)
		}
	}
	if enterpriseOption.Config.ApplicationModelExportInterval != 0 {
		if err = startApplicationModelExporter(ctx, modelServer); err != nil {
			return fmt.Errorf("failed to start json application model exporter: %w", err)
		}
	}
	if enterpriseOption.Config.EnableAlerts {
		if err = alerter.Start(pm.Server); err != nil {
			return fmt.Errorf("failed to start alerting: %w", err)
		}
		log.Info("Started alerting.")
	}

	if option.Config.HealthServerAddress != "" {
		health.StartHealthServer(ctx, option.Config.HealthServerAddress, option.Config.HealthServerInterval)
	}

	obs.AddListener(pm)
	saveInitInfo()

	// Initialize a k8s watcher used to manage policies. This should happen
	// after the sensors are loaded, otherwise existing policies will fail to
	// load on the first attempt.
	if enterpriseOption.K8SControlPlaneEnabled() {
		log.Info("Enabling policy watcher")

		// add informers for all resources
		if enterpriseOption.Config.EnablePolicyK8sWatcher {
			// NB(anna): Check this option for OSS compatibility, but it's not
			// recommended to use it to disable watching TracingPolicy in EE.
			// Use --enable-policy-k8swatcher=false instead.
			if option.Config.EnableTracingPolicyCRD {
				err = crdwatcher.AddTracingPolicyInformer(ctx, kubernetesManager.GetControllerManager(), observer.GetSensorManager())
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableSandboxPolicies {
				err = enterpriseWatcher.AddSandboxPolicyInformer(ctx, kubernetesManager.GetControllerManager(), observer.GetSensorManager())
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableAlerts {
				err = enterpriseWatcher.AddAlertRuleInformer(ctx, kubernetesManager.GetControllerManager(), alertsManager)
				if err != nil {
					return err
				}
			}
			if enterpriseOption.Config.EnableApplicationModel {
				err = netpol.AddTetragonNetworkPolicyInformer(ctx, kubernetesManager.GetControllerManager())
				if err != nil {
					return err
				}
			}
		}
	}

	obs.LogPinnedBpf(observerDir)

	if err = procevents.GetRunningProcs(); err != nil {
		return err
	}
	if err = startLayer3Progs(ctx); err != nil {
		return err
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

	if err = policies.LoadFromConfig(ctx, alertsManager, log); err != nil {
		return err
	}

	// Remove previous tetragon instance if detected
	deleteOldBpfDir(oldBpfDir)

	// k8s should have metrics, so periodically log only in a non k8s
	if !enterpriseOption.K8SControlPlaneEnabled() {
		go logStatus(ctx, obs)
	}

	return obs.StartReady(ctx, ready)
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

// getObserverDir returns the path to the observer directory based on the BPF
// map root. This function relies on the map root to be set properly via
// github.com/cilium/tetragon/pkg/bpf.CheckOrMountFS().
func getObserverDir() string {
	return bpf.MapPrefixPath()
}

// getWriter returns lumberjack logger and the absolute path to the file.
func getWriter(filename string, maxSizeMB int, maxBackups int, compress bool) (*lumberjack.Logger, error) {
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
	return writer, nil
}

func startExporter(ctx context.Context, server *server.Server) error {
	allowList, denyList, err := getExportFilters()
	if err != nil {
		return err
	}
	fieldFilters, err := getFieldFilters()
	if err != nil {
		return err
	}
	writer, err := getWriter(option.Config.ExportFilename, option.Config.ExportFileMaxSizeMB, option.Config.ExportFileMaxBackups, option.Config.ExportFileCompress)
	if err != nil {
		return err
	}
	var flowWriter *lumberjack.Logger
	enableFlowExport := enterpriseOption.Config.FlowExportFilename != ""
	if enableFlowExport {
		flowWriter, err = getWriter(enterpriseOption.Config.FlowExportFilename, enterpriseOption.Config.FlowExportFileMaxSizeMB, enterpriseOption.Config.FlowExportFileMaxBackups, enterpriseOption.Config.FlowExportFileCompress)
		if err != nil {
			return err
		}
	}

	var ocsfWriter *lumberjack.Logger
	enableOCSFClient := enterpriseOption.Config.OCSFExportServer != ""
	enableOCSFExport := enterpriseOption.Config.OCSFExportFilename != ""
	if enableOCSFExport {
		ocsfWriter, err = getWriter(enterpriseOption.Config.OCSFExportFilename, enterpriseOption.Config.OCSFExportFileMaxSizeMB, enterpriseOption.Config.OCSFExportFileMaxBackups, enterpriseOption.Config.OCSFExportFileCompress)
		if err != nil {
			return err
		}
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
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
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	exporter.Start()

	return nil
}

func startApplicationModelExporter(ctx context.Context, modelServer *model.Server) error {
	var flatWriter *lumberjack.Logger
	var writer *lumberjack.Logger
	var connectionWriter *lumberjack.Logger
	var err error

	if enterpriseOption.Config.ApplicationModelExportFilename != "" {
		writer, err = getWriter(
			enterpriseOption.Config.ApplicationModelExportFilename,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
		)
		if err != nil {
			return err
		}
	}

	if enterpriseOption.Config.TelemetryExportFilename != "" {
		flatWriter, err = getWriter(
			enterpriseOption.Config.TelemetryExportFilename,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
		)
		if err != nil {
			return err
		}
	}
	if enterpriseOption.Config.ConnectionLogFileName != "" {
		connectionWriter, err = getWriter(
			enterpriseOption.Config.ConnectionLogFileName,
			option.Config.ExportFileMaxSizeMB,
			option.Config.ExportFileMaxBackups,
			option.Config.ExportFileCompress,
		)
		if err != nil {
			return err
		}
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.Info("Periodically rotating JSON application model export files", "frequency", option.Config.ExportFileRotationInterval.String())
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.Warn("Failed to rotate JSON application model export file", logfields.Error, rotationErr,
							"file", enterpriseOption.Config.ApplicationModelExportFilename)
					}
				}
			}
		}()
	}

	go model.ExportApplicationModel(ctx, modelServer, writer, flatWriter, connectionWriter,
		enterpriseOption.Config.ApplicationModelExportInterval)

	return nil
}

func Serve(
	ctx context.Context, listenAddr string,
	srv *server.Server, model *model.Server, mandate *mandatesrv.Server, alerter tetragon.AlertServiceServer, netpol *netpol.NetworkPolicyManager) error {
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, srv)
	registerProcessModelServiceServer(grpcServer, model)
	tetragon.RegisterMandateServiceServer(grpcServer, mandate)
	tetragon.RegisterAlertServiceServer(grpcServer, alerter)
	tetragon.RegisterNetworkPolicyServiceServer(grpcServer, netpol)
	registerApplicationModelServiceServer(grpcServer, model)

	proto, addr, err := server.SplitListenAddr(listenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse listen address: %w", err)
	}
	go func(proto, addr string) {
		var listener net.Listener
		var err error
		if proto == "unix" {
			listener, err = unixlisten.ListenWithRename(addr, 0660)
		} else {
			listener, err = net.Listen(proto, addr)
		}
		if err != nil {
			logger.Fatal(log, "Failed to start gRPC server", "address", addr, "protocol", proto, logfields.Error, err)
		}
		log.Info("Starting gRPC server", "address", addr, "protocol", proto)
		if err = grpcServer.Serve(listener); err != nil {
			log.Error("Failed to close gRPC server", logfields.Error, err)
		}
	}(proto, addr)
	go func(proto, addr string) {
		<-ctx.Done()
		grpcServer.Stop()
		// if proto is unix, ListenWithRename() creates the socket
		// then renames it, so explicitly clean it up.
		if proto == "unix" {
			os.Remove(addr)
		}
	}(proto, addr)
	return nil
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
