//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

//go:build !windows

package file

import (
	"fmt"
	"maps"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type SelectorsMetadata struct {
	HasMatchBinaries        bool
	HasMatchOperations      bool
	OperationsSet           Set[tetragon.FileAction]
	HasMatchDigests         bool
	HasMatchNamespaces      bool
	HasMatchCapabilities    bool
	HasMatchRenameSrcType   bool
	HasMatchOpenFlags       bool
	HasMatchFilename        bool
	HasMatchExecAttributes  bool
	HasMatchOpenrawResult   bool
	HasMatchUidGid          bool
	HasMatchProcessDuration bool
	HasMatchActions         bool
}

func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}

func createValuesSet(values []v1alpha1.OperationSelectorValue) (Set[tetragon.FileAction], error) {
	s := NewSet[tetragon.FileAction]()

	for _, v := range values {
		val, ok := tetragon.FileAction_value[strings.ToUpper(v)]
		if !ok {
			return nil, fmt.Errorf("unknown value in matchOperation: %s", v)
		}
		s.Add(tetragon.FileAction(val))
	}

	return s, nil
}

func getAllOps() []tetragon.FileAction {
	result := []tetragon.FileAction{}
	for k := range maps.Keys(tetragon.FileAction_name) {
		if tetragon.FileAction(k) == tetragon.FileAction_FILE_INVALID {
			continue
		}
		result = append(result, tetragon.FileAction(k))
	}
	return result
}

func GetSelectorsMetadata(sel []v1alpha1.FileSelector) (*SelectorsMetadata, error) {
	meta := &SelectorsMetadata{
		HasMatchBinaries:        false,
		HasMatchOperations:      false,
		OperationsSet:           NewSet[tetragon.FileAction](),
		HasMatchDigests:         false,
		HasMatchNamespaces:      false,
		HasMatchCapabilities:    false,
		HasMatchRenameSrcType:   false,
		HasMatchOpenFlags:       false,
		HasMatchFilename:        false,
		HasMatchExecAttributes:  false,
		HasMatchOpenrawResult:   false,
		HasMatchUidGid:          false,
		HasMatchProcessDuration: false,
		HasMatchActions:         false,
	}

	for _, s := range sel {
		meta.HasMatchBinaries = If(len(s.MatchBinaries) > 0, true, meta.HasMatchBinaries)
		meta.HasMatchOperations = If(len(s.MatchOperations) > 0, true, meta.HasMatchOperations)
		meta.HasMatchDigests = If(len(s.MatchDigests) > 0, true, meta.HasMatchDigests)
		meta.HasMatchNamespaces = If(len(s.MatchNamespaces) > 0, true, meta.HasMatchNamespaces)
		meta.HasMatchCapabilities = If(len(s.MatchCapabilities) > 0, true, meta.HasMatchCapabilities)
		meta.HasMatchRenameSrcType = If(len(s.MatchRenameSrcType) > 0, true, meta.HasMatchRenameSrcType)
		meta.HasMatchFilename = If(len(s.MatchFilename) > 0, true, meta.HasMatchFilename)
		meta.HasMatchOpenFlags = If(len(s.MatchOpenFlags) > 0, true, meta.HasMatchOpenFlags)
		meta.HasMatchExecAttributes = If(len(s.MatchExecAttributes) > 0, true, meta.HasMatchExecAttributes)
		meta.HasMatchOpenrawResult = If(len(s.MatchOpenrawResult) > 0, true, meta.HasMatchOpenrawResult)
		meta.HasMatchUidGid = If(len(s.MatchUidGid) > 0, true, meta.HasMatchUidGid)
		meta.HasMatchProcessDuration = If(len(s.MatchProcessDuration) > 0, true, meta.HasMatchProcessDuration)
		meta.HasMatchActions = If(len(s.MatchActions) > 0, true, meta.HasMatchActions)
	}

	if meta.HasMatchOperations {
		for _, s := range sel {
			if len(s.MatchOperations) == 0 {
				continue
			} else if len(s.MatchOperations) > 1 {
				return nil, fmt.Errorf("only support a single matchOperation selector")
			}

			switch o := s.MatchOperations[0]; o.Operator {
			case "In":
				s, err := createValuesSet(o.Values)
				if err != nil {
					return nil, err
				}
				meta.OperationsSet = meta.OperationsSet.Union(s)
			case "NotIn":
				s, err := createValuesSet(o.Values)
				if err != nil {
					return nil, err
				}
				diff := NewSet(getAllOps()...).Difference(s)
				meta.OperationsSet = meta.OperationsSet.Union(diff)
			default:
				return nil, fmt.Errorf("matchOperation error: Only In and NotIn operators are supported")
			}
		}
	} else {
		meta.OperationsSet = NewSet(getAllOps()...)
	}

	return meta, nil
}
