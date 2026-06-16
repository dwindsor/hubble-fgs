// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package v1alpha1

import "encoding/json"

// We define a custom Unmarshaler for FileSpec to set
// monitorHostFiles default equals to true even in nok8s
// builds. This is called from json.Unmarshal when we have
// a FileSpec and is applied both in k8s and nok8s cases.
func (spec *FileSpec) UnmarshalJSON(data []byte) error {
	type fileSpec FileSpec
	ret := fileSpec{
		MonitorHostFiles: true,
	}
	if err := json.Unmarshal(data, &ret); err != nil {
		return err
	}
	*spec = FileSpec(ret)
	return nil
}
