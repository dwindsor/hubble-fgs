//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package filemetrics

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	enterpriseMetrics "github.com/isovalent/hubble-fgs/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	directionIn  = "in"
	directionOut = "out"
)

type FileError int

const (
	SensorFileRPCTerminate FileError = iota
	SensorFileRPCInitHost
	SensorFileRPCScanner
	SensorFileRPCInitCont
	SensorFileRPCDestroyCont
	SensorFileOp
	SensorFileMv
	SensorFileMvTcId
	SensorFileMvScanner
	SensorFileInitScanner
	SensorFileInitContainerScanner
	SensorFileInitPodAddScanner
	SensorFileDestroyPodUpdateScanner
	SensorFileInitPodUpdateScanner
	SensorFileDestroyPodDeleteScanner
	GrpcNilEvProc
	GrpcNotValidAction
	GrpcOpGtOne
	GrpcNotValidOp
	GrpcEventcacheRetry
)

var fileErrorLabelValues = map[FileError]string{
	SensorFileRPCTerminate:            "sensor_file_rpc_terminate",
	SensorFileRPCInitHost:             "sensor_file_rpc_init_host",
	SensorFileRPCScanner:              "sensor_file_rpc_scanner",
	SensorFileRPCInitCont:             "sensor_file_rpc_init_cont",
	SensorFileRPCDestroyCont:          "sensor_file_rpc_destroy_cont",
	SensorFileOp:                      "sensor_file_op",
	SensorFileMv:                      "sensor_file_mv",
	SensorFileMvTcId:                  "sensor_file_mv_tcid",
	SensorFileMvScanner:               "sensor_file_mv_scanner",
	SensorFileInitScanner:             "sensor_file_init_scanner",
	SensorFileInitContainerScanner:    "sensor_file_init_container_scanner",
	SensorFileInitPodAddScanner:       "sensor_file_init_podAdd_scanner",
	SensorFileDestroyPodUpdateScanner: "sensor_file_destroy_podUpdate_scanner",
	SensorFileInitPodUpdateScanner:    "sensor_file_init_podUpdate_scanner",
	SensorFileDestroyPodDeleteScanner: "sensor_file_destroy_podDelete_scanner",
	GrpcNilEvProc:                     "grpc_nil_ev_proc",
	GrpcNotValidAction:                "grpc_not_valid_action",
	GrpcOpGtOne:                       "grpc_op_gt_one",
	GrpcNotValidOp:                    "grpc_not_valid_op",
	GrpcEventcacheRetry:               "grpc_eventcache_retry",
}

func (e FileError) String() string {
	return fileErrorLabelValues[e]
}

type FileEvent int

const (
	FileEventProcess FileEvent = iota
	FileEventProcessExec
)

var fileEventLabelValues = map[FileEvent]string{
	FileEventProcess:     "process_file",
	FileEventProcessExec: "process_file_exec",
}

func (e FileEvent) String() string {
	return fileEventLabelValues[e]
}

var (
	fileTotalEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "file_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file events (independently of going through the eventcache).",
	})

	fileExecTotalEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "file_exec_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file_exec events (independently of going through the eventcache).",
	})

	fileTotalCacheEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_cache_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file events (that go in/out the eventcache).",
	}, []string{"direction"})

	fileExecTotalCacheEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_exec_cache_events_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_exec_file events (that go in/out the eventcache).",
	}, []string{"direction"})

	fileTotalActionEvents = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "file_actions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total file events per action",
	}, []string{"node", "namespace", "workload", "pod", "policy", "rule", "action", "operation"})

	fileExecTotalActionEvents = metrics.NewCounterVecWithPod(prometheus.CounterOpts{
		Name:      "file_exec_actions_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total file exec events per action",
	}, []string{"node", "namespace", "workload", "pod", "file", "digest", "action"})

	fileTotalErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of process_file event errors (can be from the grpc or sensor).",
	}, []string{"reason"})

	fileFailedDigest = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name:      "file_digest_fail_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of failures in getting the digest for process_file events.",
	}, []string{"event"})

	fileExecEbpfErrors = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "file_exec_ebpf_total"),
		"Total number of eBPF errors for process_file_exec events.",
		[]string{"error"}, nil,
	))

	fileExecCollectorErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Name:      "file_exec_collector_errors_total",
		Namespace: consts.MetricsNamespace,
		Help:      "Total number of errors during the collector runs for process_file_exec events.",
	})

	fileMapInodeFile = metrics.NewBPFGauge(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "inode_file_map_entries"),
		"Total number of entries in the inode map for files.",
		[]string{"policy"}, nil,
	))

	fileMapInodeFileMax = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "inode_file_map_max",
		Namespace: consts.MetricsNamespace,
		Help:      "Maximum number of entries in the inode map for files.",
	}, []string{"policy"})

	fileMapInodeDir = metrics.NewBPFGauge(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "inode_dir_map_entries"),
		"Total number of entries in the inode map for directories.",
		[]string{"policy"}, nil,
	))

	fileMapInodeDirMax = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:      "inode_dir_map_max",
		Namespace: consts.MetricsNamespace,
		Help:      "Maximum number of entries in the inode map for directories.",
	}, []string{"policy"})

	fileKernelErrors = metrics.NewBPFCounter(prometheus.NewDesc(
		prometheus.BuildFQName(consts.MetricsNamespace, "", "file_kernel_errors_total"),
		"Total number of eBPF errors for process_file events per hook and reason.",
		[]string{"policy", "hook", "reason"}, nil,
	))
)

func initHealthMetrics(registry *prometheus.Registry) {
	registry.MustRegister(fileTotalEvents)
	registry.MustRegister(fileExecTotalEvents)
	registry.MustRegister(fileTotalCacheEvents)
	registry.MustRegister(fileExecTotalCacheEvents)
	registry.MustRegister(fileTotalErrors)
	registry.MustRegister(fileFailedDigest)
	registry.MustRegister(fileExecCollectorErrors)
	registry.MustRegister(fileMapInodeFileMax)
	registry.MustRegister(fileMapInodeDirMax)

	// Initialize metrics with labels
	fileTotalCacheEvents.WithLabelValues(directionIn).Add(0)
	fileTotalCacheEvents.WithLabelValues(directionOut).Add(0)
	fileExecTotalCacheEvents.WithLabelValues(directionIn).Add(0)
	fileExecTotalCacheEvents.WithLabelValues(directionOut).Add(0)
	for er := range fileErrorLabelValues {
		fileTotalErrors.WithLabelValues(er.String()).Add(0)
	}
	for ev := range fileEventLabelValues {
		fileFailedDigest.WithLabelValues(ev.String()).Add(0)
	}
}

func InitHealthMetrics(registry *prometheus.Registry) {
	initHealthMetrics(registry)

	// Register custom collectors
	registry.MustRegister(NewBPFCollector())
	registry.MustRegister(NewBPFInodeMapCollector())
	registry.MustRegister(NewBPFErrorCollector())

	// NOTES:
	// * error, reason - standardize on a label
	// * event - standardize on a label (value formatting)
	// * Consider merging custom collectors into one
}

func InitHealthMetricsForDocs(registry *prometheus.Registry) {
	initHealthMetrics(registry)

	// Initialize metrics with example labels
	fileMapInodeFileMax.WithLabelValues(consts.ExamplePolicyLabel).Set(0)
	fileMapInodeDirMax.WithLabelValues(consts.ExamplePolicyLabel).Set(0)

	// Register custom zero collectors
	registry.MustRegister(NewBPFZeroCollector())
}

func InitEventsMetrics(registry *prometheus.Registry) {
	registry.MustRegister(fileTotalActionEvents)
	registry.MustRegister(fileExecTotalActionEvents)

	// NOTES:
	// * action, operation - standardize labels (+ don't confuse with ops.OpCode)
	// * Add binary and policy labels to all event metrics?
}

func InitEventsMetricsForDocs(registry *prometheus.Registry) {
	InitEventsMetrics(registry)

	// Initialize metrics with example labels
	podLabels := append([]string{enterpriseMetrics.ExampleNodeLabel}, enterpriseMetrics.ExamplePodLabels...)
	for _, operation := range tetragon.FileOperation_name {
		for _, action := range tetragon.FileAction_name {
			fileTotalActionEvents.WithLabelValues(
				append(podLabels, consts.ExamplePolicyLabel, enterpriseMetrics.ExampleDir, action, operation)...).Add(0)
		}
		fileExecTotalActionEvents.WithLabelValues(
			append(podLabels, enterpriseMetrics.ExampleFile, enterpriseMetrics.ExampleFileDigest, operation)...).Add(0)
	}
}

func FileTotalEventsInc() {
	fileTotalEvents.Inc()
}

func FileExecTotalEventsInc() {
	fileExecTotalEvents.Inc()
}

func FileTotalCacheInEventsInc() {
	fileTotalCacheEvents.WithLabelValues(directionIn).Inc()
}

func FileTotalCacheOutEventsInc() {
	fileTotalCacheEvents.WithLabelValues(directionOut).Inc()
}

func FileExecTotalCacheInEventsInc() {
	fileExecTotalCacheEvents.WithLabelValues(directionIn).Inc()
}

func FileExecTotalCacheOutEventsInc() {
	fileExecTotalCacheEvents.WithLabelValues(directionOut).Inc()
}

func FileTotalActionEventsInc(node, namespace, workload, pod, policy, rule, action, operation string) {
	fileTotalActionEvents.WithLabelValues(node, namespace, workload, pod, policy, rule, action, operation).Inc()
}

func FileExecTotalActionEventsInc(node, namespace, workload, pod, file, digest, action string) {
	fileExecTotalActionEvents.WithLabelValues(node, namespace, workload, pod, file, digest, action).Inc()
}

func FileTotalErrorsInc(er FileError) {
	fileTotalErrors.WithLabelValues(er.String()).Inc()
}

func FileFailedDigestInc(ev FileEvent) {
	fileFailedDigest.WithLabelValues(ev.String()).Inc()
}

func FileSetFileInodeMapMax(policy string, val float64) {
	fileMapInodeFileMax.WithLabelValues(policy).Set(val)
}

func FileSetDirectoryInodeMapMax(policy string, val float64) {
	fileMapInodeDirMax.WithLabelValues(policy).Set(val)
}

// bpfZeroCollector implements prometheus.Collector. It collects "zero" metrics.
// It's intended to be used when BPF metrics are not collected, but we still want
// Prometheus metrics to be exposed.
type bpfZeroCollector struct {
	collectors []prometheus.Collector
}

func NewBPFZeroCollector() prometheus.Collector {
	return &bpfZeroCollector{
		collectors: []prometheus.Collector{
			&bpfCollector{},
			&bpfInodeMapCollector{},
			&bpfErrorCollector{},
		},
	}
}

func (c *bpfZeroCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range c.collectors {
		collector.Describe(ch)
	}
}

func (c *bpfZeroCollector) Collect(ch chan<- prometheus.Metric) {
	for _, er := range fileapi.FileExecMetricTable {
		ch <- fileExecEbpfErrors.MustMetric(0, er)
	}
	ch <- fileMapInodeFile.MustMetric(0, consts.ExamplePolicyLabel)
	ch <- fileMapInodeDir.MustMetric(0, consts.ExamplePolicyLabel)
	for _, hook := range fileHookMap {
		for _, er := range fileErrorReasonMap {
			ch <- fileKernelErrors.MustMetric(0, consts.ExamplePolicyLabel, hook, er)
		}
	}
}
