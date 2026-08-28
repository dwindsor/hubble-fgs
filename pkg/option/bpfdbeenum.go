// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package option

import (
	"slices"
	"strings"

	"maps"

	"github.com/cilium/tetragon/pkg/option"
)

type BPFDbgEnum struct {
	*option.BPFDbgEnum
	fgsAreaMap map[string]uint8
}

// Wraps the *option.BPFDbgEnum coming from OSS with FGS specific values
func NewBPFDbgEnum(enum *option.BPFDbgEnum, areaMap map[string]uint8) *BPFDbgEnum {
	allowedOSS := enum.Allowed()
	allowedOSS = strings.Trim(allowedOSS, "()")
	allowedVals := strings.Split(allowedOSS, ", ")
	// Append EE specific values
	allowedVals = append(allowedVals, slices.Collect(maps.Keys(areaMap))...)
	// Make the slice stable to generate stable flags documentation.
	// Since we are collecting from a map, we need to guarantee it.
	slices.Sort(allowedVals)

	newEnum, _ := option.NewSliceEnum(allowedVals, nil)
	enum.SliceEnum = newEnum // replace the original SliceEnum with our EE one

	return &BPFDbgEnum{
		BPFDbgEnum: enum,
		fgsAreaMap: areaMap,
	}
}

func (e *BPFDbgEnum) ToFGSBPFConfig() uint8 {
	if slices.Contains(e.Values, "all") {
		return 0xff
	}
	var cfgVal uint8
	for _, v := range e.Values {
		cfgVal |= e.fgsAreaMap[v]
	}
	return cfgVal
}
