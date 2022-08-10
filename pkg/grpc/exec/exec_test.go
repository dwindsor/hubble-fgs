// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// go test -gcflags="" -c ./pkg/grpc/exec/ -o go-tests/grpc-exec.test
// sudo ./go-tests/grpc-exec.test  [ -test.run TestGrpcExec ]

package exec

import (
	"testing"

	execOSS "github.com/cilium/tetragon/pkg/grpc/exec"
)

func TestGrpcExecOutOfOrder(t *testing.T) {
	execOSS.GrpcExecOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecInOrder(t *testing.T) {
	execOSS.GrpcExecInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecMisingParent(t *testing.T) {
	execOSS.GrpcExecMisingParent[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcMissingExec(t *testing.T) {
	execOSS.GrpcMissingExec[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecParentOutOfOrder(t *testing.T) {
	execOSS.GrpcExecParentOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecCloneInOrder(t *testing.T) {
	execOSS.GrpcExecCloneInOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecCloneOutOfOrder(t *testing.T) {
	execOSS.GrpcExecCloneOutOfOrder[*MsgExecveEventUnix, *MsgCloneEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcParentRefcntInOrder(t *testing.T) {
	execOSS.GrpcParentRefcntInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoInOrder(t *testing.T) {
	execOSS.GrpcExecPodInfoInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoOutOfOrder(t *testing.T) {
	execOSS.GrpcExecPodInfoOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoInOrderAfter(t *testing.T) {
	execOSS.GrpcExecPodInfoInOrderAfter[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoOutOfOrderAfter(t *testing.T) {
	execOSS.GrpcExecPodInfoOutOfOrderAfter[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoDelayedOutOfOrder(t *testing.T) {
	execOSS.GrpcExecPodInfoDelayedOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcExecPodInfoDelayedInOrder(t *testing.T) {
	execOSS.GrpcExecPodInfoDelayedInOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}

func TestGrpcDelayedExecK8sOutOfOrder(t *testing.T) {
	execOSS.GrpcDelayedExecK8sOutOfOrder[*MsgExecveEventUnix, *MsgExitEventUnix](t)
}
