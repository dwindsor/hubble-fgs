//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

const (
	DirMapName  = "hash_map_dir_alloc"
	FileMapName = "hash_map_file_alloc"
	LpmMapName  = "lpm_trie_map_alloc"

	ScannerFifoName      = "fs_scanner.sock" // this is used for hubble-fgs-fs-scanner <-> file-sensor communication
	LocalScannerFifoPath = "/var/run"
)

var (
	ScannerFifoPath = ""
)

const (
	FilterIgnore  = 0
	FilterMatch   = 1
	FilterMonitor = 2

	AddToMap      = 0
	RemoveFromMap = 1
)

type FsScannerInit struct {
	Spec    v1alpha1.FileSpec
	MapDir  string
	PinPath string
}

type FsScannerRename struct {
	Path        string
	MapDir      string
	Op          uint32
	Action      uint32
	PinPath     string
	ContainerID string
	RuleID      uint32
}

type FsScannerContainerInit struct {
	Spec        []v1alpha1.FileSpec
	PinPath     []string
	ContainerID string
	PodNs       string
	PodName     string
	RootDir     string
	MapDir      string
}

type FsScannerContainerDestroy struct {
	PinPath     []string
	ContainerID string
	MapDir      string
}
