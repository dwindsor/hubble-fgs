// Copyright 2021 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package selectors

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

type kernelSelectorState struct {
	off uint32     // offset into encoding
	e   [4096]byte // kernel encoding of selectors
}

func writeSelectorUint32(k *kernelSelectorState, v uint32) {
	binary.LittleEndian.PutUint32(k.e[k.off:], v)
	k.off += 4
}

func writeSelectorUint64(k *kernelSelectorState, v uint64) {
	binary.LittleEndian.PutUint64(k.e[k.off:], v)
	k.off += 8
}

func writeSelectorLength(k *kernelSelectorState, loff uint32) {
	diff := k.off - loff
	binary.LittleEndian.PutUint32(k.e[loff:], diff)
}

func writeSelectorByteArray(k *kernelSelectorState, b []byte, size uint32) {
	for l := uint32(0); l < size; l++ {
		k.e[k.off+l] = b[l]
	}
	k.off += size
}

func advanceSelectorLength(k *kernelSelectorState) uint32 {
	off := k.off
	k.off += 4
	return off
}

func argSelectorValue(v string) ([]byte, uint32) {
	b := []byte(v)
	return b, uint32(len(b))
}

const (
	actionTypePost     = 0
	actionTypeFollowFd = 1
	actionTypeSigKill  = 2
)

var actionTypeTable = map[string]uint32{
	"post_event": actionTypePost,
	"followfd":   actionTypeFollowFd,
	"sigkill":    actionTypeSigKill,
}

var actionTypeStringTable = map[uint32]string{
	actionTypePost:     "post_event",
	actionTypeFollowFd: "followfd",
	actionTypeSigKill:  "sigkill",
}

const (
	argTypeNop       = 0
	argTypeInt       = 1
	argTypeCharBuf   = 2
	argTypeCharIovec = 3
	argTypeSizet     = 4
	argTypeSkb       = 5
	argTypeString    = 6

	argTypeS64 = 10
	argTypeU64 = 11
	argTypeS32 = 12
	argTypeU32 = 13

	argTypeFile = 16
	argTypeFd   = 17
)

var argTypeTable = map[string]uint32{
	"int":        argTypeInt,
	"uint32":     argTypeU32,
	"int32":      argTypeS32,
	"uint64":     argTypeU64,
	"int64":      argTypeS64,
	"char_buf":   argTypeCharBuf,
	"char_iovec": argTypeCharIovec,
	"sizet":      argTypeSizet,
	"skb":        argTypeSkb,
	"string":     argTypeString,
	"fd":         argTypeFd,
	"file":       argTypeFile,
}

var argTypeStringTable = map[uint32]string{
	argTypeInt:       "int",
	argTypeU32:       "uint32",
	argTypeS32:       "int32",
	argTypeU64:       "uint64",
	argTypeS64:       "int64",
	argTypeCharBuf:   "char_buf",
	argTypeCharIovec: "char_iovec",
	argTypeSizet:     "sizet",
	argTypeSkb:       "skb",
	argTypeString:    "string",
	argTypeFd:        "fd",
	argTypeFile:      "file",
}

const (
	selectorOpGT  = 1
	selectorOpLT  = 2
	selectorOpEQ  = 3
	selectorOpNEQ = 4
	// Pid ops
	selectorOpIn    = 5
	selectorOpNotIn = 6
	// String ops
	selectorOpContains = 7
	selectorOpPrefix   = 8
	selectorOpPostfix  = 9
)

// The kernel side could learn this but it would require a reference
// to the arg type. Its easier to type check up front and insert the
// type in the encoding.
const (
	valueTypeNil    = 0
	valueTypeUint32 = 1
	valueTypeUint64 = 2
	valueTypeInt32  = 3
	valueTypeInt64  = 4
	valueTypeString = 5
)

func selectorOp(op string) (uint32, error) {
	switch op {
	case "gt":
		return selectorOpGT, nil
	case "lt":
		return selectorOpLT, nil
	case "eq", "Equal":
		return selectorOpEQ, nil
	case "neq":
		return selectorOpNEQ, nil
	case "In":
		return selectorOpIn, nil
	case "NotIn":
		return selectorOpNotIn, nil
	case "prefix", "Prefix":
		return selectorOpPrefix, nil
	case "postfix", "Postfix":
		return selectorOpPostfix, nil
	}

	return 0, fmt.Errorf("Unknown op '%s'", op)
}

const (
	pidNamespacePid = 0x1
	pidFollowForks  = 0x2
)

func pidSelectorFlags(pid *v1alpha1.PIDSelector) uint32 {
	flags := uint32(0)

	if pid.IsNamespacePID {
		flags |= pidNamespacePid
	}
	if pid.FollowForks {
		flags |= pidFollowForks
	}
	return flags
}

func pidSelectorValue(pid *v1alpha1.PIDSelector) ([]byte, uint32) {
	b := make([]byte, len(pid.Values)*4)

	for i, v := range pid.Values {
		off := i * 4
		binary.LittleEndian.PutUint32(b[off:], v)
	}
	return b, uint32(len(b))
}

func parseMatchPid(k *kernelSelectorState, pid *v1alpha1.PIDSelector) error {
	op, err := selectorOp(pid.Operator)
	if err != nil {
		return fmt.Errorf("matchpid error: %s\n", err)
	}
	writeSelectorUint32(k, op)

	flags := pidSelectorFlags(pid)
	writeSelectorUint32(k, flags)

	value, size := pidSelectorValue(pid)
	writeSelectorUint32(k, size/4)
	writeSelectorByteArray(k, value, size)
	return nil
}

func parseMatchPids(k *kernelSelectorState, matchPids []v1alpha1.PIDSelector) error {
	loff := advanceSelectorLength(k)
	for _, p := range matchPids {
		if err := parseMatchPid(k, &p); err != nil {
			return err
		}
	}
	writeSelectorLength(k, loff)
	return nil
}

func kprobeArgType(t string) uint32 {
	return argTypeTable[t]
}

func ArgTypeToString(t uint32) string {
	return argTypeStringTable[t]
}

func argSelectorType(arg *v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg) (uint32, error) {
	for _, s := range sig {
		if arg.Index == s.Index {
			// TBD: We shouldn't get this far with invalid KProbe args
			// KProbe args have already been validated
			return kprobeArgType(s.Type), nil
		}
	}
	return 0, fmt.Errorf("argFilter for unknown index")
}

func parseMatchValues(k *kernelSelectorState, values []string, ty uint32) error {
	for _, v := range values {
		switch ty {
		case argTypeFd, argTypeFile:
			mnt := "/"
			swapV := mnt + reader.SwapPath(v)
			value, size := argSelectorValue(swapV)
			writeSelectorUint32(k, size)
			writeSelectorByteArray(k, value, size)
		case argTypeString, argTypeCharBuf:
			value, size := argSelectorValue(v)
			writeSelectorUint32(k, size)
			writeSelectorByteArray(k, value, size)
		case argTypeU32, argTypeS32, argTypeInt, argTypeSizet:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %x", v, err)
			}
			writeSelectorUint32(k, uint32(i))
		case argTypeU64, argTypeS64:
			i, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("MatchArgs value %s invalid: %x", v, err)
			}
			writeSelectorUint64(k, uint64(i))
		case argTypeSkb, argTypeCharIovec:
			return fmt.Errorf("MatchArgs values %s unsupported\n", v)
		}
	}
	return nil
}

func parseMatchArg(k *kernelSelectorState, arg *v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg) error {
	writeSelectorUint32(k, arg.Index)

	op, err := selectorOp(arg.Operator)
	if err != nil {
		return fmt.Errorf("matcharg error: %s\n", err)
	}
	writeSelectorUint32(k, op)
	moff := advanceSelectorLength(k)
	ty, err := argSelectorType(arg, sig)
	if err != nil {
		return fmt.Errorf("argSelector error: %s\n", err)
	}
	writeSelectorUint32(k, ty)
	err = parseMatchValues(k, arg.Values, ty)
	if err != nil {
		return fmt.Errorf("parseMatchValues error: %s\n", err)
	}
	writeSelectorLength(k, moff)
	return err
}

func parseMatchArgs(k *kernelSelectorState, args []v1alpha1.ArgSelector, sig []v1alpha1.KProbeArg) error {
	loff := advanceSelectorLength(k)
	for _, a := range args {
		if err := parseMatchArg(k, &a, sig); err != nil {
			return err
		}
	}
	writeSelectorLength(k, loff)
	return nil
}

func parseMatchAction(k *kernelSelectorState, action *v1alpha1.ActionSelector) error {
	act, ok := actionTypeTable[action.Action]
	if !ok {
		return fmt.Errorf("parseMatchAction: actionType %s unknown\n", action.Action)
	}
	writeSelectorUint32(k, act)
	switch act {
	case actionTypeFollowFd:
		writeSelectorUint32(k, action.ArgFd)
		writeSelectorUint32(k, action.ArgName)
	}
	return nil
}

func parseMatchActions(k *kernelSelectorState, actions []v1alpha1.ActionSelector) error {
	loff := advanceSelectorLength(k)
	for _, a := range actions {
		if err := parseMatchAction(k, &a); err != nil {
			return err
		}
	}
	writeSelectorLength(k, loff)
	return nil
}

func parseSelector(
	k *kernelSelectorState,
	selectors *v1alpha1.KProbeSelector,
	args []v1alpha1.KProbeArg) error {
	if err := parseMatchPids(k, selectors.MatchPIDs); err != nil {
		return fmt.Errorf("parseMatchPids error: %x", err)
	}
	if err := parseMatchArgs(k, selectors.MatchArgs, args); err != nil {
		return fmt.Errorf("parseMatchArgs  error: %x", err)
	}
	if err := parseMatchActions(k, selectors.MatchActions); err != nil {
		return fmt.Errorf("parseMatchActions error: %x", err)
	}
	return nil
}

// array := [number][filter1][filter2][...][filtern]
// filter := [length][matchPIDs][matchArgs]
// matchPIDs := [num][PID1][PID2]...[PIDn]
// matchArgs := [num][ARGx][ARGy]...[ARGn]
// PIDn := [op][flags][value]
// Argn := [index][op][value]
// value := [type][len][v]
func InitKernelSelectors(spec v1alpha1.KProbeSpec) ([4096]byte, error) {
	selectors := spec.Selectors
	args := spec.Args
	kernelSelectors := &kernelSelectorState{}
	totaloff := 2

	writeSelectorUint32(kernelSelectors, uint32(len(selectors)))
	soff := make([]uint32, len(selectors))
	for i, _ := range selectors {
		soff[i] = advanceSelectorLength(kernelSelectors)
		totaloff++
	}
	for i, s := range selectors {
		writeSelectorLength(kernelSelectors, soff[i])
		loff := advanceSelectorLength(kernelSelectors)
		if err := parseSelector(kernelSelectors, &s, args); err != nil {
			return kernelSelectors.e, err
		}
		writeSelectorLength(kernelSelectors, loff)
	}
	return kernelSelectors.e, nil
}

func InitTracepointSelectors(spec *v1alpha1.TracepointSpec) ([4096]byte, error) {
	selectors := spec.Selectors
	args := spec.Args
	kernelSelectors := &kernelSelectorState{}
	totaloff := 2

	writeSelectorUint32(kernelSelectors, uint32(len(selectors)))
	soff := make([]uint32, len(selectors))
	for i, _ := range selectors {
		soff[i] = advanceSelectorLength(kernelSelectors)
		totaloff++
	}
	for i, s := range selectors {
		writeSelectorLength(kernelSelectors, soff[i])
		loff := advanceSelectorLength(kernelSelectors)
		if err := parseSelector(kernelSelectors, &s, args); err != nil {
			return kernelSelectors.e, err
		}
		writeSelectorLength(kernelSelectors, loff)
	}
	return kernelSelectors.e, nil
}
