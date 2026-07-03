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

import (
	"bytes"
	"encoding/json"
)

// UnmarshalJSON defines a custom Unmarshaler for FileSpec to set
// monitorHostFiles default equals to true even in nok8s
// builds. This is called from json.Unmarshal when we have
// a FileSpec and is applied both in k8s and nok8s cases.
//
// We decode strictly (DisallowUnknownFields) so that unknown or misplaced
// fields under spec.file are rejected instead of silently dropped. Without
// this, the lenient default json.Unmarshal would ignore unknown selectors,
// loading the policy without the intended filtering. This makes the file
// subtree consistent with the rest of the spec, which already rejects unknown
// fields, and it applies to both k8s and nok8s builds.
func (spec *FileSpec) UnmarshalJSON(data []byte) error {
	type fileSpec FileSpec
	ret := fileSpec{
		MonitorHostFiles: true,
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ret); err != nil {
		return err
	}
	*spec = FileSpec(ret)
	return nil
}
