package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/dns"
	"github.com/isovalent/hubble-fgs/pkg/encoder"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/isovalent/hubble-fgs/pkg/metrics/metricsconfig"
	"github.com/isovalent/hubble-fgs/pkg/nscache"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	"github.com/isovalent/hubble-fgs/pkg/podinfo"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/exporter"
	"github.com/cilium/tetragon/pkg/filters"
	fgsGrpc "github.com/cilium/tetragon/pkg/grpc"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/ratelimit"
	"github.com/cilium/tetragon/pkg/server"
	"github.com/cilium/tetragon/pkg/tgsyscall"
	"github.com/cilium/tetragon/pkg/unixlisten"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/cilium/tetragon/pkg/watcher"
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/cilium/tetragon/pkg/watcher/crd"

	// Imported to allow sensors to be initialized inside init().
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	_ "github.com/isovalent/hubble-fgs/pkg/sensors/sockmap"

	// Add enterprise-specific filters to the global registry
	_ "github.com/isovalent/hubble-fgs/pkg/filters"

	"github.com/cilium/lumberjack/v2"
	gops "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
	v1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsinformer "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions/apiextensions/v1"
	"k8s.io/client-go/kubernetes"
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

func getExportFilters() ([]*tetragon.Filter, []*tetragon.Filter, error) {
	allowList, err := filters.ParseFilterList(viper.GetString(keyExportAllowlist), viper.GetBool(keyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	denyList, err := filters.ParseFilterList(viper.GetString(keyExportDenylist), viper.GetBool(keyEnablePidSetFilter))
	if err != nil {
		return nil, nil, err
	}
	return allowList, denyList, nil
}

func getFieldFilters() ([]*tetragon.FieldFilter, error) {
	fieldFilters := viper.GetString(keyFieldFilters)

	filters, err := filters.ParseFieldFilterList(fieldFilters)
	if err != nil {
		return nil, err
	}

	return filters, nil
}

func saveInitInfo() error {
	info := bugtool.InitInfo{
		ExportFname: option.Config.ExportFilename,
		LibDir:      option.Config.HubbleLib,
		BtfFname:    option.Config.BTF,
		MetricsAddr: option.Config.MetricsServer,
		ServerAddr:  option.Config.ServerAddress,
	}
	return bugtool.SaveInitInfo(&info)
}

var (
	fgsCgroupPath = "/run/tetragon/cgroup2"
)

func DetachTetragonCgroups(tgTypes, bestEffort bool) error {
	httpSockfd := int(0)
	tlsSockfd := int(0)
	nopSockfd := int(0)

	cgrpfd, err := unix.Open(fgsCgroupPath, unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open '%s': %w", fgsCgroupPath, err)
	}
	defer unix.Close(cgrpfd)

	// walk maps to find sockmap so we can detach skmsg skskb and nop
	mapID := ebpf.MapID(0)
	for {
		mapID, err = ebpf.MapGetNextID(mapID)
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(mapID)
		if err != nil {
			break
		}
		defer m.Close()
		if m.Type() == ebpf.SockHash {
			n := m.String()
			if strings.Contains(n, "http_sock_map") {
				httpSockfd = m.FD()
			}
			if strings.Contains(n, "tls_sock_map") {
				tlsSockfd = m.FD()
			}
			if strings.Contains(n, "nop_sock_map") {
				nopSockfd = m.FD()
			}
		}
	}

	// Finds a specific map associated with the program protocol type
	findSockFD := func(n string) int {
		fd := int(0)
		if strings.Contains(n, "http") {
			fd = httpSockfd
		} else if strings.Contains(n, "tls") {
			fd = tlsSockfd
		} else if strings.Contains(n, "nop") {
			fd = nopSockfd
		} else {
			log.WithField("mapName", n).Warn("Discovered SkMsg program with unknown name")
		}
		return fd
	}

	progID := ebpf.ProgramID(0)
	for {
		progID, err = ebpf.ProgramGetNextID(progID)
		if err != nil {
			break
		}

		prog, err := ebpf.NewProgramFromID(progID)
		if err != nil {
			continue
		}
		defer prog.Close()

		n := prog.String()
		// For now do the dumb thing and just attempt to detach from
		// things we know we could be attached to. With some guardrails
		// to only work on programs with names  we recognize.
		switch prog.Type() {
		case ebpf.CGroupSKB:
			if bestEffort {
				if !strings.Contains(n, "inet_send") &&
					!strings.Contains(n, "inet_recv") &&
					!strings.Contains(n, "inet_lazy_recv") &&
					!strings.HasPrefix(n, "tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") {
					break
				}
			} else {
				break
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
				Attach:  ebpf.AttachCGroupInetIngress,
			}
			link.RawDetachProgram(opts)
			opts.Attach = ebpf.AttachCGroupInetEgress
			link.RawDetachProgram(opts)
		case ebpf.SkMsg:
			if bestEffort {
				if !strings.Contains(n, "http_skmsg") &&
					!strings.Contains(n, "tls_skmsg") &&
					!strings.Contains(n, "nop_skmsg") &&
					!strings.HasPrefix(n, "tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") {
					break
				}
			} else {
				break
			}

			sockfd := findSockFD(n)
			if sockfd == 0 {
				break
			}

			opts := link.RawDetachProgramOptions{
				Target:  sockfd,
				Program: prog,
				Attach:  ebpf.AttachSkMsgVerdict,
			}
			link.RawDetachProgram(opts)
		case ebpf.SkSKB:
			if bestEffort {
				if !strings.Contains(n, "bpf_http_parser") &&
					!strings.Contains(n, "bpf_http_verdict") &&
					!strings.Contains(n, "bpf_tls_skskb") &&
					!strings.Contains(n, "bpf_nop_") &&
					!strings.HasPrefix(n, "tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") {
					break
				}
			} else {
				break
			}

			sockfd := findSockFD(n)
			if sockfd == 0 {
				break
			}

			opts := link.RawDetachProgramOptions{
				Target:  sockfd,
				Program: prog,
				Attach:  ebpf.AttachSkSKBStreamVerdict,
			}
			link.RawDetachProgram(opts)
			opts.Attach = ebpf.AttachSkSKBStreamParser
			link.RawDetachProgram(opts)
			opts.Attach = ebpf.AttachSkSKBVerdict
			link.RawDetachProgram(opts)
		case ebpf.SockOps:
			if bestEffort {
				if !strings.Contains(n, "fgs") &&
					!strings.HasPrefix(n, "tg_") {
					break
				}
			} else if tgTypes {
				if !strings.HasPrefix(n, "tg_") {
					break
				}
			} else {
				break
			}
			opts := link.RawDetachProgramOptions{
				Target:  cgrpfd,
				Program: prog,
				Attach:  ebpf.AttachCGroupSockOps,
			}
			link.RawDetachProgram(opts)
		}
	}
	return nil
}

func hubbleFGSExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, tgsyscall.SIGRTMIN_20,
		tgsyscall.SIGRTMIN_21, tgsyscall.SIGRTMIN_22)

	// Logging should always be bootstrapped first. Do not add any code above this!
	if err := logger.SetupLogging(option.Config.LogOpts, option.Config.Debug); err != nil {
		log.Fatal(err)
	}

	if option.Config.RBSize != 0 && option.Config.RBSizeTotal != 0 {
		log.Fatalf("Can't specify --rb-size and --rb-size-total together")
	}

	log.WithField("version", version.Version).Info("Starting Tetragon Enterprise")
	log.WithField("config", viper.AllSettings()).Info("config settings")

	if viper.IsSet(keyNetnsDir) {
		defaults.NetnsDir = viper.GetString(keyNetnsDir)
	}

	// Setup file system mounts
	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.CheckOrMountCgroup2()

	// Raise memory resource
	bpf.ConfigureResourceLimits()

	// Get observer bpf maps and programs directory
	observerDir := getObserverDir()
	option.Config.BpfDir = observerDir
	option.Config.MapDir = observerDir

	// Check if option to remove old BPF and maps is enabled.
	if option.Config.ReleasePinned {
		// Always release tg_ prefix as we are relatively sure these belong to us
		// but, do more aggressive detach op to clean up old versioned programs when
		// told.
		if err := DetachTetragonCgroups(true, enterpriseOption.Config.DetachOldBpf); err != nil {
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
	obs := observer.NewObserver(option.Config.TracingPolicy)
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

	// start sensor manager, and have it wait on sensorMgWait until we load
	// the base sensor. note that this means that calling methods on the
	// manager will block so they will have to either be executed in a
	// goroutine or after we close the sensorMgWait channel to avoid
	// deadlock.
	sensorMgWait := make(chan struct{})
	defer func() {
		// if we fail before closing the channel, close it so that
		// the sensor manager routine is unblocked.
		if sensorMgWait != nil {
			close(sensorMgWait)
		}
	}()
	if err := obs.InitSensorManager(sensorMgWait); err != nil {
		return fmt.Errorf("failed to start sensor manager: %w", err)
	}
	defer func() {
		observer.RemoveSensors(ctx)
	}()

	// Remove old tcpmon BPF directory
	//
	// commit https://github.com/cilium/tetragon/commit/f1a37fc2dfbf5827611ad5b9db966502ecdb0db9
	// in OSS, changed the prefix where the bpf maps and programs should be pinned from "tcpmon"
	// to "tetragon".
	// commit https://github.com/isovalent/hubble-fgs/commit/642115d3b8d2283f4463bbc2208f4a959e93ba24
	// imported that change in v1.9.0-rc3.
	// Users upgrading from older (e.g., v1.8 versions) might end up with duplicated maps and
	// programs. We have no upgrade method, so completely remove the directory.
	oldBpfDir := filepath.Join(bpf.GetMapRoot(), "tcpmon")
	if err := os.RemoveAll(oldBpfDir); err != nil {
		log.Warnf("faied to clean %s. Consider removing it manually", oldBpfDir)
	}

	/* Remove any stale programs, otherwise feature set change can cause
	 * old programs to linger resulting in undefined behavior. And because
	 * we recapture current running state from proc and/or have cache of
	 * events no state should be lost/missed.
	 */
	obs.RemovePrograms()
	os.Mkdir(defaults.DefaultRunDir, os.ModeDir)

	err := btf.InitCachedBTF(option.Config.HubbleLib, option.Config.BTF)
	if err != nil {
		return fmt.Errorf("failed to init cached BTF: %w", err)
	}

	if err := observer.InitDataCache(option.Config.DataCacheSize); err != nil {
		return err
	}

	if option.Config.MetricsServer != "" {
		go metrics.EnableMetrics(option.Config.MetricsServer)
		metricsconfig.InitAllMetrics(metrics.GetRegistry())
		go enterpriseMetrics.StartPodDeleteHandler()
		// Handler must be registered before the watcher is started
		metrics.RegisterPodDeleteHandler()
	}

	// Probe runtime configuration and do not fail on errors
	obs.UpdateRuntimeConf(option.Config.MapDir)

	var k8sWatcher watcher.K8sResourceWatcher
	if option.Config.EnableK8s {
		log.Info("Enabling Kubernetes API")
		crds := map[string]struct{}{
			v1alpha1.TPName:           {},
			v1alpha1.TPNamespacedName: {},
		}
		if option.Config.EnablePodInfo {
			crds[v1alpha1.PIName] = struct{}{}
		}
		config, err := k8sconf.K8sConfig()
		if err != nil {
			return err
		}
		log.WithField("crds", crds).Info("Waiting for required CRDs")
		var wg sync.WaitGroup
		wg.Add(1)
		k8sClient := kubernetes.NewForConfigOrDie(config)
		crdClient := apiextensionsclientset.NewForConfigOrDie(config)
		crdInformer := apiextensionsinformer.NewCustomResourceDefinitionInformer(crdClient, 0*time.Second, nil)
		_, err = crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
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
		if option.Config.EnablePodInfo {
			k8sWatcher = watcher.NewK8sWatcherWithTetragonClient(k8sClient, versioned.NewForConfigOrDie(config), 60*time.Second)
		} else {
			k8sWatcher = watcher.NewK8sWatcher(k8sClient, 60*time.Second)
		}
	} else {
		log.Info("Disabling Kubernetes API")
		k8sWatcher = watcher.NewFakeK8sWatcher(nil)
	}
	_, err = cilium.InitCiliumState(ctx, option.Config.EnableCilium)
	if err != nil {
		return fmt.Errorf("failed to init cilium state: %w", err)
	}

	if err := process.InitCache(k8sWatcher, option.Config.ProcessCacheSize); err != nil {
		return fmt.Errorf("failed to init process cache: %w", err)
	}
	podinfo.SetK8sResourceWatcher(k8sWatcher)

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

	pm, err := fgsGrpc.NewProcessManager(
		ctx,
		&cleanupWg,
		observer.GetSensorManager(),
		hookRunner)
	if err != nil {
		return fmt.Errorf("failed to create process manager: %w", err)
	}
	if err = Serve(ctx, option.Config.ServerAddress, pm.Server); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}
	if option.Config.ExportFilename != "" {
		if err = startExporter(ctx, pm.Server, k8sWatcher); err != nil {
			return fmt.Errorf("failed to start json exporter: %w", err)
		}
	}

	log.WithField("enabled", option.Config.ExportFilename != "").WithField("fileName", option.Config.ExportFilename).Info("Exporter configuration")
	obs.AddListener(pm)
	saveInitInfo()
	if option.Config.EnableK8s {
		go crd.WatchTracePolicy(ctx, observer.GetSensorManager())
	}

	obs.LogPinnedBpf(observerDir)

	// Load default base sensors
	base := base.GetInitialSensor()
	if err := base.Load(observerDir, observerDir); err != nil {
		return fmt.Errorf("hubble-fgs, aborting could not load BPF programs: %w", err)
	}
	defer func() {
		base.Unload()
	}()

	// now that the base sensor was loaded, we can start the sensor manager
	close(sensorMgWait)
	sensorMgWait = nil
	observer.GetSensorManager().LogSensorsAndProbes(ctx)

	if len(option.Config.TracingPolicy) > 0 {
		tp, err := tracingpolicy.FromFile(option.Config.TracingPolicy)
		if err != nil {
			return fmt.Errorf("failed to read config: %w", err)
		}
		err = observer.GetSensorManager().AddTracingPolicy(ctx, tp)
		if err != nil {
			return fmt.Errorf("failed to get sensors from parser policy: %w", err)
		}
	}

	// k8s should have metrics, so periodically log only in a non k8s
	if option.Config.EnableK8s == false {
		go logStatus(ctx, obs)
	}

	return obs.Start(ctx)
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
	// For non k8s deployments we explicitly want log files
	// with permission 0600
	if !option.Config.EnableK8s {
		writer.FileMode = os.FileMode(0600)
	}

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

func startExporter(ctx context.Context, server *server.Server, watcher watcher.K8sResourceWatcher) error {
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

	encoder := encoder.NewJSONEncoder(writer, flowWriter, watcher, enableFlowExport)
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
	log.WithFields(logrus.Fields{"fieldFilters": fieldFilters}).Debug("Configured field filters")
	log.WithFields(logrus.Fields{"logger": writer, "request": &req}).Info("Starting JSON exporter")
	exporter := exporter.NewExporter(ctx, &req, server, encoder, writer, rateLimiter)
	exporter.Start()
	return nil
}

func Serve(ctx context.Context, listenAddr string, srv *server.Server) error {
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, srv)
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

func resizeCaches() error {
	if err := dns.ResizeCache(enterpriseOption.Config.DnsCacheSize); err != nil {
		return err
	}
	return nscache.ResizeCache(enterpriseOption.Config.NetNsCacheSize)
}

func execute() error {
	rootCmd := &cobra.Command{
		Use:   "tetragon",
		Short: "Run the Tetragon Enterprise agent",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(os.Args) > 0 {
				if path.Base(os.Args[0]) == "hubble-fgs" {
					logger.GetLogger().Warn("The name 'hubble-fgs' has been deprecated and is going away, please use 'tetragon' instead.")
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			readAndSetFlags()
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
		readConfigSettings(adminFgsConfDir, adminFgsConfDropIn, packageFgsConfDropIns)
	})

	flags := rootCmd.PersistentFlags()

	flags.String(keyConfigDir, "", "Configuration directory that contains a file for each option")
	flags.BoolP(keyDebug, "d", false, "Enable debug messages. Equivalent to '--log-level=debug'")
	flags.String(keyHubbleLib, "/var/lib/hubble-fgs/", "Location of hubble libs (btf and bpf files)")
	flags.String(keyBTF, "", "Location of btf")

	flags.String(keyProcFS, "/proc/", "Location of procfs to consume existing PIDs")
	flags.String(keyKernelVersion, "", "Kernel version")
	flags.Int(keyVerbosity, 0, "set verbosity level")
	flags.Int(keyProcessCacheSize, 65536, "Size of the process cache")
	flags.Int(keyDataCacheSize, 1024, "Size of the data events cache")
	flags.Bool(keyForceSmallProgs, false, "Force loading small programs, even in kernels with >= 5.3 versions")
	flags.String(keyExportFilename, "", "Filename for JSON export. Disabled by default")
	flags.Int(keyExportFileMaxSizeMB, 10, "Size in MB for rotating JSON export files")
	flags.Duration(keyExportFileRotationInterval, 0, "Interval at which to rotate JSON export files in addition to rotating them by size")
	flags.Int(keyExportFileMaxBackups, 5, "Number of rotated JSON export files to retain")
	flags.Bool(keyExportFileCompress, false, "Compress rotated JSON export files")
	flags.Int(keyExportRateLimit, -1, "Rate limit (per minute) for event export. Set to -1 to disable")

	flags.String(keyLogLevel, "info", "Set log level")
	flags.String(keyLogFormat, "text", "Set log format")
	flags.Bool(keyEnableK8sAPI, false, "Access Kubernetes API to associate Tetragon events with Kubernetes pods")
	flags.Bool(keyEnableCiliumAPI, false, "Access Cilium API to associate Tetragon events with Cilium endpoints and DNS cache")
	flags.String(keyMetricsServer, "", "Metrics server address (e.g. ':2112'). Disabled by default")
	flags.String(keyServerAddress, "localhost:54321", "gRPC server address (e.g. 'localhost:54321' or 'unix:///var/run/tetragon/tetragon.sock')")
	flags.String(keyGopsAddr, "", "gops server address (e.g. 'localhost:8118'). Disabled by default")
	flags.Bool(keyEnableProcessCred, false, "Enable process_cred events")
	flags.Bool(keyEnableProcessNs, false, "Enable namespace information in process_exec and process_kprobe events")
	flags.Uint(keyEventQueueSize, 10000, "Set the size of the internal event queue.")
	flags.String(keyProtocolShift, "auto", "(deprecated)")

	// Tracing Policy files
	flags.String(keyTracingPolicy, "", "Tracing policy file to load at startup")
	// --config-file is the deprecated flag for the new --tracing-policy
	flags.String(keyConfigFile, "", "Configuration file to load from")
	flags.MarkHidden(keyConfigFile)

	// JSON export aggregation options.
	flags.Bool(keyEnableExportAggregation, false, "Enable JSON export aggregation")
	flags.Duration(keyExportAggregationWindowSize, 15*time.Second, "JSON export aggregation time window")
	flags.Uint64(keyExportAggregationBufferSize, 10000, "Aggregator channel buffer size")

	// JSON export filter options
	flags.String(keyExportAllowlist, "", "JSON export allowlist")
	flags.String(keyExportDenylist, "", "JSON export denylist")

	// Field filters options for export
	flags.String(keyFieldFilters, "", "Field filters for event exports")

	// Network namespace options
	flags.String(keyNetnsDir, "/var/run/docker/netns/", "Network namespace dir")

	// Provide option to remove existing pinned BPF programs and maps in Tetragon's
	// observer dir on startup. Useful for doing upgrades/downgrades. Set to false to
	// disable.
	flags.Bool(keyReleasePinnedBPF, true, "Release all pinned BPF programs and maps in Tetragon BPF directory. Enabled by default. Set to false to disable")

	// Allow to disable kprobe multi interface
	flags.Bool(keyDisableKprobeMulti, false, "Allow to disable kprobe multi interface")

	// Allow to specify perf ring buffer size
	flags.Int(keyRBSizeTotal, 0, "Set perf ring buffer size in total for all cpus (default 65k per cpu)")
	flags.Int(keyRBSize, 0, "Set perf ring buffer size for single cpu (default 65k)")

	// Provide option to enable policy filtering. Because the code is new,
	// this is set to false by default.
	flags.Bool(keyEnablePolicyFilter, false, "Enable policy filter (beta) code")
	flags.Bool(keyEnablePolicyFilterDebug, false, "Enable policy filter debug messages")
	flags.Bool(keyEnablePodInfo, false, "Enable getting additional Kubernetes metadata from PodInfo custom resources")

	enterpriseOption.AddEnterpriseFlags(flags)

	viper.BindPFlags(flags)
	return rootCmd.Execute()
}
