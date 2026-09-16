// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows && !nok8s

package server

import (
	"time"

	"github.com/cilium/tetragon/pkg/cgidmap"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/process"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sys/unix"

	"github.com/isovalent/hubble-fgs/pkg/metrics/appmodelmetrics"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
)

const podSandboxImageName = "Pod-Sandbox-Image"
const podSandboxName = "Pod-Sandbox"

// newKtimeConverter reads CLOCK_BOOTTIME once and records the offset.
// Falls back to a zero-value converter (all conversions return nil) on error.
func newKtimeConverter() ktimeConverter {
	// Use CLOCK_BOOTTIME (monotonic=false) since BPF uses ktime_get_boot_ns()
	// when available. This ensures correct timestamp conversion after
	// system suspend/resume cycles.
	var bt unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt); err != nil {
		return ktimeConverter{}
	}
	// base = now - boottime, so that base.Add(ktime) gives the wall-clock time.
	base := time.Now().Add(-time.Duration(bt.Nano()))
	return ktimeConverter{base: base}
}

var cgmap cgidmap.Map

func initContainerIDMap() error {
	var err error
	cgmap, err = cgidmap.GlobalMap()
	if cgmap == nil || err != nil {
		return err
	}

	return nil
}

func getContainerInfo(cgroupid uint64, cgroupIdToContainerInfoCache *lru.Cache[uint64, *types.ContainerInfo]) *types.ContainerInfo {
	containerInfo, ok := cgroupIdToContainerInfoCache.Get(cgroupid)
	if ok {
		return containerInfo
	}

	containerInfo = &types.ContainerInfo{}

	cid, ok := cgmap.Get(cgroupid)
	if ok && cid != "" {
		logger.GetLogger().Debug("Found container id for cgroupid", "cgroupid", cgroupid, "cid", cid)
		containerInfo.Id = cid

		podInfo := process.GetPodInfo(containerInfo.Id, "", "", 0)
		if podInfo == nil {
			logger.GetLogger().Error("No pod info found", "containerInfo.Id", containerInfo.Id)
			appmodelmetrics.RecordLookupError(appmodelmetrics.LookupPod)
			return nil
		}

		containerInfo.Name = podInfo.Container.Name
		containerInfo.Image = podInfo.Container.Image.Name
	} else {
		sandboxId, ok := cgmap.GetPodSandbox(cgroupid)
		if ok && sandboxId != "" {
			logger.GetLogger().Debug("Found sandbox id for cgroupid", "cgroupid", cgroupid, "sandboxId", sandboxId)
			containerInfo.Id = sandboxId
			containerInfo.Name = podSandboxName
			containerInfo.Image = podSandboxImageName
		} else {
			logger.GetLogger().Info("No container info found for process", "cgroupid", cgroupid)
			appmodelmetrics.RecordLookupError(appmodelmetrics.LookupContainer)
			return nil
		}
	}

	cgroupIdToContainerInfoCache.Add(cgroupid, containerInfo)

	return containerInfo

}
