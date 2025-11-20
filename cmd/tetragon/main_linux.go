// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tetragon

import (
	"context"

	ossAlignchecker "github.com/cilium/tetragon/pkg/alignchecker"
	"github.com/cilium/tetragon/pkg/btf"
	ossconfig "github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/reader/namespace"
	"github.com/cilium/tetragon/pkg/reader/proc"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/grpc"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/alignchecker"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base/procfs"
	"github.com/isovalent/hubble-fgs/pkg/sensors/file"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/cgroup"
)

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
