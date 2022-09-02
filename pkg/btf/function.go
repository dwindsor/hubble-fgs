// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package btf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/tetragon/pkg/logger"
)

func getTypeInternal(sb *strings.Builder, myType interface{}, fnName string, kretprobe bool) {
	switch t := myType.(type) {
	case *btf.Pointer:
		arg := myType.(*btf.Pointer)
		switch arg.Target.(type) {
		case *btf.FuncProto:
			getTypeInternal(sb, arg.Target, "(*p)", true)
		default:
			getTypeInternal(sb, arg.Target, "", true)
			sb.WriteString("*")
		}
	case *btf.Int:
		sb.WriteString("int")
	case *btf.Const:
		sb.WriteString("const ")
		arg := myType.(*btf.Const)
		getTypeInternal(sb, arg.Type, "", true)
	case *btf.Typedef:
		arg := myType.(*btf.Typedef)
		sb.WriteString(arg.Name)
	case *btf.Void:
		sb.WriteString("void")
	case *btf.FuncProto:
		arg := myType.(*btf.FuncProto)
		if kretprobe {
			getTypeInternal(sb, arg.Return, "", true)
			sb.WriteString(" ")
		}
		sb.WriteString(fnName)
		sb.WriteString("(")
		for i := 0; i < len(arg.Params); i++ {
			getTypeInternal(sb, arg.Params[i].Type, "", true)
			if i != len(arg.Params)-1 {
				sb.WriteString(", ")
			}
		}
		sb.WriteString(")")
	case *btf.Struct:
		arg := myType.(*btf.Struct)
		sb.WriteString(fmt.Sprintf("struct %s", arg.Name))
	default:
		logger.GetLogger().Warnf("Unknown type %s", t)
	}
}

func getType(myType interface{}, fnName string, kretprobe bool) string {
	var sb strings.Builder
	getTypeInternal(&sb, myType, fnName, kretprobe)
	return sb.String()
}

// This function gets a function name and returns it's prototype
// based on the BTF.
//
// An example here is that if the user provides fnName ="vfs_mkdir"
// it returns "vfs_mkdir(struct inode*, struct dentry*, umode_t)".
// In the case where kretprobe is true, it also includes the return
// type (i.e. "int vfs_mkdir(struct inode*, struct dentry*, umode_t)").
func GetFuncProto(spec *btf.Spec, fnName string, kretprobe bool) string {
	var fnType *btf.Func
	if err := spec.TypeByName(fnName, &fnType); err != nil {
		logger.GetLogger().Errorf("LoadKernelSpec %w", err)
	}
	fnProto := fnType.Type.(*btf.FuncProto)
	return getType(fnProto, fnName, kretprobe)
}
