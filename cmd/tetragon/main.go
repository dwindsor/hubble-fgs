package main

import (
	"context"
	"fmt"
	"io/fs"
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
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/isovalent/hubble-fgs/pkg/alignchecker"
	"github.com/isovalent/hubble-fgs/pkg/cilium"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
	"github.com/isovalent/hubble-fgs/pkg/k8s/client/clientset/versioned"
	"github.com/isovalent/hubble-fgs/pkg/mandate"
	mandatesrv "github.com/isovalent/hubble-fgs/pkg/mandate/server"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	enterpriseMetricsConfig "github.com/isovalent/hubble-fgs/pkg/metricsconfig"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	processcacheclean "github.com/isovalent/hubble-fgs/pkg/process"
	"github.com/isovalent/hubble-fgs/pkg/sandboxpolicy"
	"github.com/isovalent/hubble-fgs/pkg/svcinfo"
	enterpriseWatcher "github.com/isovalent/hubble-fgs/pkg/watcher"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ossAlignchecker "github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/filters"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/cilium/tetragon/pkg/watcher/crdwatcher"

	// Imported to allow sensors to be initialized inside init().
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/procevents"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	// Add enterprise-specific filters to the global registry
	_ "github.com/isovalent/hubble-fgs/pkg/filters"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logger.GetLogger()
)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func checkStructAlignments() error {
	bpfObjPath := path.Join(option.Config.HubbleLib, "bpf_alignchecker_oss.o")
	if err := ossAlignchecker.CheckStructAlignments(bpfObjPath); err != nil {
		return err
	}
	bpfObjPath = path.Join(option.Config.HubbleLib, "bpf_alignchecker.o")
	return alignchecker.CheckStructAlignments(bpfObjPath)
}

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
		log.WithFields(logrus.Fields{"redactionFilters": redactionFilters}).Info("Configured redaction filters")
	} else {
		log.WithError(err).Error("Error configuring redaction filters")
	}
	return err
}

func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: option.Config.ExportFilename,
		LibDir:      option.Config.HubbleLib,
		BtfFname:    option.Config.BTF,
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
		log.WithField("file", option.Config.MemProfile).Info("Stopping mem profiling")
		f, err := os.Create(option.Config.MemProfile)
		if err != nil {
			log.WithField("file", option.Config.MemProfile).Fatal("Could not create memory profile: ", err)
		}
		defer f.Close()
		// get up-to-date statistics
		runtime.GC()
		if err := pprof.WriteHeapProfile(f); err != nil {
			log.Fatal("could not write memory profile: ", err)
		}
	}
	if option.Config.CpuProfile != "" {
		log.WithField("file", option.Config.CpuProfile).Info("Stopping cpu profiling")
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
		log.WithField("path", old).
			Info("Found bpf leftover instance, removing")
	}
	// rename current tetragon instance to tetragon_old
	if err := os.Rename(path, old); err != nil {
		return "", err
	}
	log.Infof("Found bpf instance: %s, moved to: %s", path, old)
	return old, nil
}

func deleteOldBpfDir(path string) {
	if path == "" {
		return
	}
	if err := os.RemoveAll(path); err != nil {
		log.WithError(err).
			WithField("path", path).
			Error("Failed to remove old bpf instance")
		return
	}
	log.Infof("Removed bpf instance: %s", path)
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
		log.Fatal(err)
	}

	if filepath.IsAbs(option.Config.TracingPolicyDir) == false {
		log.Fatalf("Failed path specified by --tracing-policy-dir '%q' is not absolute", option.Config.TracingPolicyDir)
	}
	option.Config.TracingPolicyDir = filepath.Clean(option.Config.TracingPolicyDir)

	if option.Config.RBSize != 0 && option.Config.RBSizeTotal != 0 {
		log.Fatalf("Can't specify --rb-size and --rb-size-total together")
	}

	log.WithField("version", version.Version).Info("Starting Tetragon Enterprise")
	log.WithField("config", viper.AllSettings()).Info("config settings")

	// Log early security context in case something fails
	proc.LogCurrentSecurityContext()

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

	log.WithFields(logrus.Fields{
		"pid":     pid,
		"pidfile": defaults.DefaultPidFile,
	}).Info("Tetragon pid file creation succeeded")

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
	_, err = namespace.InitHostNamespace()
	if err != nil {
		log.WithField("procfs", option.Config.ProcFS).WithError(err).Fatalf("Failed to initialize host namespaces")
	}

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	if option.Config.PprofAddr != "" {
		go func() {
			log.Infof("Starting pprof via HTTP on %s", option.Config.PprofAddr)
			if err := servePprof(option.Config.PprofAddr); err != nil {
				log.Warnf("Failed serving pprof via HTTP: %v", err)
			}
		}()
	}

	// Start profilers first as we have to capture them in signal handling
	if option.Config.MemProfile != "" {
		log.WithField("file", option.Config.MemProfile).Info("Starting mem profiling")
	}

	if option.Config.CpuProfile != "" {
		f, err := os.Create(option.Config.CpuProfile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		log.WithField("file", option.Config.CpuProfile).Info("Starting cpu profiling")
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
		return fmt.Errorf("Failed to move old tetragon base directory: %w", err)
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
		if err := cgroup.DetachTetragonCgroups(true, enterpriseOption.Config.DetachOldBpf); err != nil {
			log.WithError(err).Warn("Failed to detach cgroups, Consider removing it manually")
		} else {
			log.Info("Successfully released attched cgroups.")
		}
		if err := os.RemoveAll(observerDir); err != nil {
			log.WithField("bpf-dir", observerDir).WithError(err).Warn("Failed to release pinned BPF programs and map, Consider removing it manually")
		} else {
			log.WithField("bpf-dir", observerDir).Info("Successfully released pinned BPF programs and maps")
		}
	}

	// Get observer from configFile
	obs := observer.NewObserver()
	defer func() {
		file.TerminateFsScanner()
		obs.PrintStats()
	}()

	defaultLevel := logger.GetLogLevel()
	go func() {
		for {
			s := <-sigs
			switch s {
			case syscall.SIGINT, syscall.SIGTERM:
				// if we receive a signal, call cancel so that contexts are finalized, which will
				// leads to normally return from tetragonExecute().
				log.Infof("Received signal %s, shutting down...", s)
				cancel()
				return
			case tgsyscall.SIGRTMIN_20: // SIGRTMIN+20
				currentLevel := logger.GetLogLevel()
				if currentLevel == logrus.DebugLevel {
					log.Infof("Received signal SIGRTMIN+20: LogLevel is already '%s'", currentLevel)
				} else {
					logger.SetLogLevel(logrus.DebugLevel)
					log.Infof("Received signal SIGRTMIN+20: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel())
				}
			case tgsyscall.SIGRTMIN_21: // SIGRTMIN+21
				currentLevel := logger.GetLogLevel()
				if currentLevel == logrus.TraceLevel {
					log.Infof("Received signal SIGRTMIN+21: LogLevel is already '%s'", currentLevel)
				} else {
					logger.SetLogLevel(logrus.TraceLevel)
					log.Infof("Received signal SIGRTMIN+21: switching from LogLevel '%s' to '%s'", currentLevel, logger.GetLogLevel())
				}
			case tgsyscall.SIGRTMIN_22: // SIGRTMIN+22
				logger.SetLogLevel(defaultLevel)
				log.Infof("Received signal SIGRTMIN+22: resetting original LogLevel '%s'", logger.GetLogLevel())
			}
		}
	}()

	if err := obs.InitSensorManager(); err != nil {
		return fmt.Errorf("failed to start sensor manager: %w", err)
	}

	err = btf.InitCachedBTF(option.Config.HubbleLib, option.Config.BTF)
	if err != nil {
		return fmt.Errorf("failed to init cached BTF: %w", err)
	}

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

	// Initialize K8s watcher
	var k8sWatcher watcher.K8sResourceWatcher
	if option.Config.EnableK8s {
		log.Info("Enabling Kubernetes API")
		// retrieve k8s clients
		config, err := k8sconf.K8sConfig()
		if err != nil {
			return err
		}
		if err = waitCRDs(config); err != nil {
			return err
		}
		k8sClient := kubernetes.NewForConfigOrDie(config)
		crdClient := versioned.NewForConfigOrDie(config)

		// create k8s watcher
		k8sWatcher = watcher.NewK8sWatcher(k8sClient, crdClient, 60*time.Second)

		// add informers for all resources
		realK8sWatcher := k8sWatcher.(*watcher.K8sWatcher)
		err = watcher.AddPodInformer(realK8sWatcher, true)
		if err != nil {
			return err
		}
		if option.Config.EnableTracingPolicyCRD {
			err = crdwatcher.AddTracingPolicyInformer(ctx, k8sWatcher, observer.GetSensorManager())
			if err != nil {
				return err
			}
		}
		if option.Config.EnablePodInfo {
			// NB(anna): Service and PodInfo informers also provide metadata
			// for the process tree. Should we tie it to the podinfo flag?
			// Should we check the process tree flag here?
			err = enterpriseWatcher.AddServiceInformer(k8sWatcher)
			if err != nil {
				return err
			}
			err = enterpriseWatcher.AddPodInfoInformer(k8sWatcher)
			if err != nil {
				return err
			}
		}
		if enterpriseOption.Config.EnableSandboxPolicies && enterpriseOption.Config.EnableSandboxPoliciesCRD {
			err = enterpriseWatcher.AddSandboxPolicyInformer(ctx, k8sWatcher, observer.GetSensorManager())
			if err != nil {
				return err
			}
		}
		// TODO(anna): Add an option to load AlertRules from a file and disable watching CRD.
		if enterpriseOption.Config.EnableAlerts {
			err = enterpriseWatcher.AddAlertRuleInformer(k8sWatcher)
			if err != nil {
				return err
			}
		}
	} else {
		log.Info("Disabling Kubernetes API")
		k8sWatcher = watcher.NewFakeK8sWatcher(nil)
	}
	// start k8s watcher
	k8sWatcher.Start()

	_, err = cilium.InitCiliumState(ctx, enterpriseOption.Config.EnableCilium, enterpriseOption.Config.EnableCiliumDNSCache)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}

	pcGCInterval := option.Config.ProcessCacheGCInterval
	if pcGCInterval <= 0 {
		pcGCInterval = defaults.DefaultProcessCacheGCInterval
	}

	if err := process.InitCache(k8sWatcher, option.Config.ProcessCacheSize, pcGCInterval); err != nil {
		return fmt.Errorf("failed to init process cache: %w", err)
	}
	podinfo.SetK8sResourceWatcher(k8sWatcher)
	svcinfo.SetK8sResourceWatcher(k8sWatcher)

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

	hookRunner := rthooks.GlobalRunner().WithWatcher(k8sWatcher)

	err = setRedactionFilters()
	if err != nil {
		return err
	}

	modelServer, err := model.DefaultNewServer()
	if err != nil {
		return err
	}

	// Load initial sensor before we start the server,
	// so it's there before we allow to load policies.
	if err = loadInitialSensor(ctx); err != nil {
		return err
	}
	if err = file.LoadFIMInitialSensor(ctx); err != nil {
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
		var err error
		mandateMgr, err = mandate.NewManager(mandateConf, observer.GetSensorManager())
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
	if err = Serve(ctx, option.Config.ServerAddress, pm.Server, modelServer, mandatesrv.New(mandateMgr)); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}
	if option.Config.ExportFilename != "" {
		if err = startExporter(ctx, pm.Server); err != nil {
			return fmt.Errorf("failed to start json exporter: %w", err)
		}
	}
	if enterpriseOption.Config.ProcessTreeExportInterval != 0 && enterpriseOption.Config.ProcessTreeExportFilename != "" {
		if err = startProcessTreeExporter(ctx, modelServer); err != nil {
			return fmt.Errorf("failed to start json application model exporter: %w", err)
		}
	}

	if enterpriseOption.Config.EnableAlerts {
		if err = alerts.StartAlerting(ctx, pm.Server); err != nil {
			return fmt.Errorf("failed to start alerting: %w", err)
		}
		log.Info("Started alerting.")
	}

	if option.Config.HealthServerAddress != "" {
		health.StartHealthServer(ctx, option.Config.HealthServerAddress, option.Config.HealthServerInterval)
	}

	obs.AddListener(pm)
	saveInitInfo()

	obs.LogPinnedBpf(observerDir)

	if err = procevents.GetRunningProcs(); err != nil {
		return err
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

	err = loadTpFromDir(ctx, option.Config.TracingPolicyDir)
	if err != nil {
		return err
	}

	if len(option.Config.TracingPolicy) > 0 {
		err = addTracingPolicy(ctx, option.Config.TracingPolicy)
		if err != nil {
			return err
		}
	}

	if len(enterpriseOption.Config.SandboxPolicies) > 0 {
		if enterpriseOption.Config.EnableSandboxPolicies {
			sm := observer.GetSensorManager()
			for _, fname := range enterpriseOption.Config.SandboxPolicies {
				err = sandboxpolicy.AddSandboxPolicyFromYAML(ctx, log, sm, fname)
				if err != nil {
					return err
				}
			}
		} else {
			log.WithField(
				"sandboxpolicies",
				enterpriseOption.Config.SandboxPolicies,
			).Fatal("sandbox policies specified but the feature is disabled")
		}
	}

	// Remove previous tetragon instance if detected
	deleteOldBpfDir(oldBpfDir)

	// k8s should have metrics, so periodically log only in a non k8s
	if option.Config.EnableK8s == false {
		go logStatus(ctx, obs)
	}

	return obs.StartReady(ctx, ready)
}

func waitCRDs(config *rest.Config) error {
	crds := make(map[string]struct{})

	if option.Config.EnableTracingPolicyCRD {
		crds[v1alpha1.TPName] = struct{}{}
		crds[v1alpha1.TPNamespacedName] = struct{}{}
	}

	if option.Config.EnablePodInfo {
		crds[v1alpha1.PIName] = struct{}{}
	}

	if enterpriseOption.Config.EnableSandboxPolicies && enterpriseOption.Config.EnableSandboxPoliciesCRD {
		crds[client.SandboxPolicyCRD.ResName] = struct{}{}
		crds[client.SandboxPolicyNamespacedCRD.ResName] = struct{}{}
	}

	crds[client.AlertRuleCRD.ResName] = struct{}{}

	if len(crds) == 0 {
		log.Info("No CRDs are enabled")
		return nil
	}

	log.WithField("crds", crds).Info("Waiting for required CRDs")
	var wg sync.WaitGroup
	wg.Add(1)
	crdClient := apiextensionsclientset.NewForConfigOrDie(config)
	crdInformer := apiextensionsinformer.NewCustomResourceDefinitionInformer(crdClient, 0*time.Second, nil)
	_, err := crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crdObject, ok := obj.(*v1.CustomResourceDefinition)
			if !ok {
				log.WithField("obj", obj).Warn("Received an invalid object")
				return
			}
			if _, ok := crds[crdObject.Name]; ok {
				log.WithField("crd", crdObject.Name).Info("Found CRD")
				delete(crds, crdObject.Name)
				if len(crds) == 0 {
					log.Info("Found all the required CRDs")
					wg.Done()
				}
			}
		},
	})
	if err != nil {
		log.WithError(err).Error("failed to add event handler")
		return err
	}
	stop := make(chan struct{})
	go func() {
		crdInformer.Run(stop)
	}()
	wg.Wait()
	close(stop)
	return nil
}

func loadTpFromDir(ctx context.Context, dir string) error {
	tpMaxDepth := 1
	tpFS := os.DirFS(dir)

	if dir == defaults.DefaultTpDir {
		// If the default directory does not exist then do not fail
		// Probably tetragon not fully installed, users did not create
		// /etc/tetragon/tetragon.tp.d/
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.WithField("tracing-policy-dir", dir).Info("Loading Tracing Policies from directory ignored, directory does not exist")
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

		if st.Mode().IsRegular() == false {
			return nil
		}

		return addTracingPolicy(ctx, file)
	})

	return err
}

func addTracingPolicy(ctx context.Context, file string) error {
	f, err := filepath.Abs(filepath.Clean(file))
	if err != nil {
		return err
	}

	tp, err := tracingpolicy.FromFile(f)
	if err != nil {
		return fmt.Errorf("failed to read tracing policy: %w", err)
	}

	err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
	if err != nil {
		return fmt.Errorf("failed to get sensors from parser policy: %w", err)
	}

	namespace := ""
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	logger.GetLogger().WithFields(logrus.Fields{
		"TracingPolicy":      file,
		"metadata.namespace": namespace,
		"metadata.name":      tp.TpName(),
	}).Info("Added TracingPolicy with success")

	return nil
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
		log.WithError(err).Warnf("Failed to parse export file permission '%s', failing back to %v",
			option.KeyExportFilePerm, perms)
	}
	writer.FileMode = perms

	finfo, err := os.Stat(filepath.Clean(writer.Filename))
	if err == nil && finfo.IsDir() {
		// Error if exportFilename points to a directory
		return nil, fmt.Errorf("passed export JSON logs file point to a directory")
	}
	abspath, err := filepath.Abs(filepath.Clean(writer.Filename))
	if err != nil {
		log.WithError(err).WithField("filename", writer.Filename).Warn("Failed to get absolute path of export file", writer.Filename)
	} else {
		log.WithField("filename", abspath).Info("Initialized export file")

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

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.WithFields(logrus.Fields{"frequency": option.Config.ExportFileRotationInterval.String()}).Info("Periodically rotating JSON export files")
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.WithError(rotationErr).WithField("file", option.Config.ExportFilename).Warn("Failed to rotate JSON export file")
					}
					if flowWriter != nil {
						log.WithField("file", enterpriseOption.Config.FlowExportFilename).Info("Rotating JSON flow export file")
						if rotationErr := flowWriter.Rotate(); rotationErr != nil {
							log.WithError(rotationErr).WithField("file", enterpriseOption.Config.FlowExportFilename).Warn("Failed to rotate JSON flow export file")
						}
					}
				}
			}
		}()
	}

	nodeIPs := encoder.GetNodeIPs()
	// Track how many bytes are written to the event export location
	encoderWriter := exporter.NewExportedBytesTotalWriter(writer)
	encoder := encoder.NewJSONEncoder(encoderWriter, flowWriter, enableFlowExport, nodeIPs)
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
	log.WithFields(logrus.Fields{"fieldFilters": fieldFilters}).Info("Configured field filters")
	log.WithFields(logrus.Fields{"logger": writer, "request": &req}).Info("Starting JSON exporter")
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	exporter.Start()

	return nil
}

func startProcessTreeExporter(ctx context.Context, modelServer *model.Server) error {
	writer, err := getWriter(
		enterpriseOption.Config.ProcessTreeExportFilename,
		option.Config.ExportFileMaxSizeMB,
		option.Config.ExportFileMaxBackups,
		option.Config.ExportFileCompress,
	)
	if err != nil {
		return err
	}

	if option.Config.ExportFileRotationInterval < 0 {
		// Passed an invalid interval let's error out
		return fmt.Errorf("frequency '%s' at which to rotate JSON export files is negative", option.Config.ExportFileRotationInterval.String())
	} else if option.Config.ExportFileRotationInterval > 0 {
		log.WithFields(logrus.Fields{
			"frequency": option.Config.ExportFileRotationInterval.String(),
		}).Info("Periodically rotating JSON application model export files")
		go func() {
			ticker := time.NewTicker(option.Config.ExportFileRotationInterval)
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if rotationErr := writer.Rotate(); rotationErr != nil {
						log.WithError(rotationErr).WithField(
							"file", enterpriseOption.Config.ProcessTreeExportFilename,
						).Warn("Failed to rotate JSON application model export file")
					}
				}
			}
		}()
	}

	go model.ExportProcessModel(ctx, modelServer, writer, enterpriseOption.Config.ProcessTreeExportInterval)

	return nil
}

func Serve(ctx context.Context, listenAddr string, srv *server.Server, model *model.Server, mandate *mandatesrv.Server) error {
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, srv)
	tetragon.RegisterProcessModelServiceServer(grpcServer, model)
	tetragon.RegisterMandateServiceServer(grpcServer, mandate)
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
			log.WithError(err).WithField("protocol", proto).WithField("address", addr).Fatal("Failed to start gRPC server")
		}
		log.WithField("address", addr).WithField("protocol", proto).Info("Starting gRPC server")
		if err = grpcServer.Serve(listener); err != nil {
			log.WithError(err).Error("Failed to close gRPC server")
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

	log.WithField("addr", option.Config.GopsAddr).Info("Starting gops server")

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
	if err := dns.ResizeCache(enterpriseOption.Config.DnsCacheSize); err != nil {
		return err
	}
	return nscache.ResizeCache(enterpriseOption.Config.NetNsCacheSize)
}

func execute() error {
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
					log.WithError(err).Fatal("Failed to generate docs")
				}
				return
			}
			if err := option.ReadAndSetFlags(); err != nil {
				log.WithError(err).Fatal("Failed to parse command line flags")
			}

			enterpriseOption.ReadAndSetEnterpriseFlags()

			// Unfortunately, due to an over-reliance on init() throughout the codebase,
			// we have to rely on resizing the caches here rather than simply initializing
			// them. (Otherwise we'd require a bunch of refactors and NewCache calls in
			// a lot of different places.) This should be fine to do as the operation
			// shouldn't be prohibitively expensive and the caches won't actually have any
			// entries yet.
			if err := resizeCaches(); err != nil {
				log.WithError(err).Fatal("Failed to configure caches")
			}

			if err := startGopsServer(); err != nil {
				log.WithError(err).Fatal("Failed to start gops")
			}

			if err := hubbleFGSExecute(); err != nil {
				log.WithError(err).Fatal("Failed to start tetragon")
			}
		},
	}

	cobra.OnInitialize(func() {
		newEnv, err := validateEnv()
		if err != nil {
			// Warn about errors but do not fail, we will default to old
			// FGS_ environment to not break users.
			log.WithError(err).Warn("Failed to validate environment variables, using old 'FGS_' environment vars")
		}
		newConf, err := validateConfig()
		if err != nil {
			log.WithError(err).Fatal("Failed to validate configuration")
		}
		if newConf {
			readConfigSettings(newEnv, newConf, adminTgConfDir, adminTgConfDropIn, packageTgConfDropIns)
		} else {
			// Warn users about using old configuration directories /etc/hubble-fgs/
			log.Warnf("Configuration directory '%s' has been deprecated, please use '%s' instead or --%s flag",
				oldAdminFgsConfDir, adminTgConfDir, option.KeyConfigDir)
			readConfigSettings(newEnv, newConf, oldAdminFgsConfDir, oldAdminFgsConfDropIn, packageTgConfDropIns)
		}
	})

	flags := rootCmd.PersistentFlags()

	option.AddFlags(flags)
	enterpriseOption.FixUpOSSFlags(flags)
	enterpriseOption.AddEnterpriseFlags(flags)

	viper.BindPFlags(flags)
	return rootCmd.Execute()
}
