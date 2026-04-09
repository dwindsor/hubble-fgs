//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build nok8s

package file

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/api/fileapi"
	pol "github.com/isovalent/hubble-fgs/pkg/sensors/file/policy"
	fm "github.com/isovalent/hubble-fgs/pkg/sensors/file/utils"
)

func addFileMonitoringSensorK8s(
	_ tracingpolicy.TracingPolicy,
	_ v1alpha1.FileSpec,
	_ TpMode,
	_ *fm.KernelSelectorState,
	_ map[fileapi.InodeKey]fileapi.InodeVal,
	_ map[string][]string,
	_ *pol.FileMonitoring,
) (int, int) {
	return 0, 0
}
