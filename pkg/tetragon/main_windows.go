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

	"golang.org/x/sys/windows/svc"

	"google.golang.org/grpc"

	"github.com/cilium/tetragon/pkg/logger/logfields"

	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3"
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

// resolveUnixSocketPath: Windows has no unix socket sidecar listener.
func resolveUnixSocketPath(_ string) (string, bool) {
	return "", false
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

func startNetworkInterfaceStats(ctx context.Context) error {
	return nil
}

func startSockopsSensor(ctx context.Context) error {
	return nil
}

func startSockmapSensor(ctx context.Context) error {
	return nil
}

func startNopSensor(ctx context.Context) error {
	return nil
}

func startHttpSensor(ctx context.Context) error {
	return nil
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

func isRunningAsWinService() bool {
	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Error("failed to determine if running as a service", logfields.Error, err)
		return false
	}
	return inService
}

func hubbleFGSExecute() error {
	if !isRunningAsWinService() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		return tetragonExecuteCtx(ctx, cancel, func() {})
	}
	return runAsWindowsService()
}
