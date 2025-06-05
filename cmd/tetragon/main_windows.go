// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tetragon

import (
	"context"

	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
	"google.golang.org/grpc"
)

func logCurrentSecurityContext() {
}

func initHostNamespaces() error {
	return nil
}

func checkProcFS() {

}

func getDefaultNewServer() (*model.Server, error) {
	return nil, nil

}

func initCachedBTF(_, _ string) error {
	return nil
}

func checkStructAlignments() error {
	return nil
}

func setNetNSDir() {
}

func detachTetragonCgroups(_, _ bool) error {
	return nil
}

func terminateFsScanner() error {
	return nil
}

func loadFIMInitialSensor(_ context.Context) error {
	return nil
}

func startLayer3Progs(ctx context.Context) error {
	return layer3.LoadWinTCPSensor(ctx)
}

func loadInitialProcFsSensor(_ context.Context) error {
	return nil
}

func procFSWalk() error {
	return nil
}

func registerProcessModelServiceServer(_ *grpc.Server, _ *model.Server) {
}

func registerApplicationModelServiceServer(_ *grpc.Server, _ *model.Server) {
}
