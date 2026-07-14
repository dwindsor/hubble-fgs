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

	ossAlignchecker "github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/checkprocfs"
	ossconfig "github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	"github.com/cilium/tetragon/pkg/server"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/grpc"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/alignchecker"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base/procfs"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/network"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

// resolveUnixSocketPath returns the in-pod unix socket path for listenAddr:
// "unix://X" yields X, a TCP address yields the default socket path, an empty
// or invalid address yields none.
func resolveUnixSocketPath(listenAddr string) (string, bool) {
	if listenAddr == "" {
		return "", false
	}
	proto, addr, err := server.SplitListenAddr(listenAddr)
	if err != nil {
		return "", false
	}
	if proto == "unix" {
		return addr, true
	}
	return defaults.DefaultUnixSocket, true
}

func logCurrentSecurityContext() {
	proc.LogCurrentSecurityContext()
}

func initHostNamespaces() error {
	_, err := namespace.InitHostNamespace()
	return err
}

func initCachedBTF(lib, btf_string string) error {
	return btf.InitCachedBTF(lib, btf_string)
}

func checkStructAlignments() error {
	bpfObjPath, err := ossconfig.FindProgramFile("bpf_alignchecker_oss.o")
	if err != nil {
		return err
	}
	if err := ossAlignchecker.CheckStructAlignmentsDefault(bpfObjPath); err != nil {
		return err
	}
	bpfObjPath, err = ossconfig.FindProgramFile("bpf_alignchecker.o")
	if err != nil {
		return err
	}
	return alignchecker.CheckStructAlignments(bpfObjPath)
}

func detachTetragonCgroups(tgTypes, bestEffort bool) error {
	return cgroup.DetachTetragonCgroups(tgTypes, bestEffort)
}

func terminateFsScanner() error {
	return file.TerminateFsScanner()
}

func loadFIMInitialSensor(ctx context.Context) error {
	return file.LoadFIMInitialSensor(ctx)
}

func startLayer3Progs(ctx context.Context) error {
	return layer3.StartLayer3Progs(ctx, nil)
}

func startNetworkInterfaceStats(ctx context.Context) error {
	return network.StartNetworkInterfaceStats(ctx)
}

func loadInitialProcFsSensor(ctx context.Context) error {
	return procfs.LoadInitialSensor(ctx)
}

func procFSWalk() error {
	return procfs.ProcFSWalk()
}

func getDefaultNewServer() (*model.Server, error) {
	return model.DefaultNewServer()

}

func registerProcessModelServiceServer(s *grpc.Server, model *model.Server) {
	tetragon.RegisterProcessModelServiceServer(s, model)
}

func registerApplicationModelServiceServer(s *grpc.Server, model *model.Server) {
	appModelV1.RegisterApplicationModelServiceServer(s, model)
}

func hubbleFGSExecute() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	return tetragonExecuteCtx(ctx, cancel, func() {})
}

func updateServiceStarting() {
}

func checkProcFS() {
	checkprocfs.Check()
}
