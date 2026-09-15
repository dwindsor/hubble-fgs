// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package types

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

type DestinationStats struct {
	Policy                string
	RuleName              string
	TxBytes               uint64
	RxBytes               uint64
	TxDropBytes           uint64
	DefaultAllowBytes     uint64
	DefaultDenyBytes      uint64
	Sessions              uint64
	TxDropPackets         uint64
	DefaultAllowPackets   uint64
	DefaultDenyPackets    uint64
	RxDropBytes           uint64
	RxDropPackets         uint64
	RxDefaultDropBytes    uint64
	RxDefaultDropPackets  uint64
	RxDefaultAllowBytes   uint64
	RxDefaultAllowPackets uint64
}

type Service struct {
	Name           string
	Namespace      string
	UID            string
	SelectorLabels map[string]string
}

type SecurityContext struct {
	// True if this container is priviledged.
	Privileged bool
}

type Image struct {
	Id string
	// Name of the container image composed of the registry path and the tag.
	Name string
}

type Container struct {
	Id        string
	Name      string
	Image     *Image
	StartTime *timestamppb.Timestamp
	Pid       uint32
	// If this is set true, it means that the process might have been originated from
	// a Kubernetes exec probe. For this field to be true, the following must be true:
	//  1. The binary field matches the first element of the exec command list for either
	//     liveness or readiness probe excluding the basename. For example, "/bin/ls"
	//     and "ls" are considered a match.
	//  2. The arguments field exactly matches the rest of the exec command list.
	MaybeExecProbe bool
	// The security context of the container
	SecurityContext *SecurityContext
}

type Pod struct {
	Namespace string
	// Name of the Pod.
	Name string
	// Container of the Pod from which the process that triggered the event
	// originates.
	Container *Container
	// Contains all the labels of the pod.
	PodLabels map[string]string // Kubernetes workload of the Pod.
	Workload  string
	// Kubernetes workload kind (e.g. "Deployment", "DaemonSet") of the Pod.
	WorkloadKind string
	WorkloadUID  string
	// Contains all the annotations of the pod.
	PodAnnotations map[string]string
}

type Destination struct {
	DestinationNames   []string
	DestinationPod     *Pod
	Port               uint32
	Stats              *DestinationStats
	DestinationService *Service
	Protocol           uint32
	// DestinationIP is the resolved peer IP address for plain-IP and CIDR
	// destinations. It is set instead of DestinationNames so the destination
	// classifies as a plain IP rather than being misfiled as a DNS name.
	DestinationIP string
}

type Workload struct {
	Name string
	Kind string
	UID  string
}

type ProcessModel struct {
	Binary     string
	BinaryArgs string
	Parent     string
	ParentArgs string
	Parents    []string // All unique immediate parent names for this binary/args tuple
	ExecIDs    []string
	Namespace  string
	Workload   *Workload
	Container  *ContainerInfo
	Dest       []*Destination
	// If set to true, this process is containerized and is a member of the
	// process tree rooted at pid=1 in its PID namespace. This is useful if,
	// for example, you wish to discern whether a process was spawned using a
	// tool like nsenter or kubectl exec.
	InInitTree      bool
	Syscalls        []uint32
	Abi             string
	FirstStartTime  *time.Time
	LatestStartTime *time.Time
	LatestExitTime  *time.Time
	ExecCount       uint64
	ExitCount       uint64
}
