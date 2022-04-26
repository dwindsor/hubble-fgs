//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package reader

import (
	"bytes"
	"strings"
	"syscall"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/kfreeapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tracingapi"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func FromCString(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}

func DecodeCommonFlags(flags uint32) []string {
	var s []string
	if (flags & api.EventExecve) != 0 {
		s = append(s, "execve")
	}
	// nolint We still want to support this even though it's deprecated
	if (flags & api.EventExecveAt) != 0 {
		s = append(s, "execveat")
	}
	if (flags & api.EventProcFS) != 0 {
		s = append(s, "procFS")
	}
	if (flags & api.EventTruncFilename) != 0 {
		s = append(s, "truncFilename")
	}
	if (flags & api.EventTruncArgs) != 0 {
		s = append(s, "truncArgs")
	}
	if (flags & api.EventTaskWalk) != 0 {
		s = append(s, "taskWalk")
	}
	if (flags & api.EventMiss) != 0 {
		s = append(s, "miss")
	}
	if (flags & api.EventNeedsAUID) != 0 {
		s = append(s, "auid")
	}
	if (flags & api.EventErrorFilename) != 0 {
		s = append(s, "errorFilename")
	}
	if (flags & api.EventErrorArgs) != 0 {
		s = append(s, "errorArgs")
	}
	if (flags & api.EventNoCWDSupport) != 0 {
		s = append(s, "nocwd")
	}
	if (flags & api.EventRootCWD) != 0 {
		s = append(s, "rootcwd")
	}
	if (flags & api.EventErrorCWD) != 0 {
		s = append(s, "errorCWD")
	}
	if (flags & api.EventClone) != 0 {
		s = append(s, "clone")
	}
	if (flags & api.EventDockerNameErr) != 0 {
		s = append(s, "errorDockerNameCwd")
	}
	if (flags & api.EventDockerKnErr) != 0 {
		s = append(s, "errorDockerKn")
	}
	if (flags & api.EventDockerSubsysCgrpErr) != 0 {
		s = append(s, "errorDockerSubsysCgrp")
	}
	if (flags & api.EventDockerSubsysErr) != 0 {
		s = append(s, "errorDockerSubsys")
	}
	if (flags & api.EventDockerCgroupsErr) != 0 {
		s = append(s, "errorDockerCgroups")
	}
	if (flags & api.EventErrorMountPoints) != 0 {
		s = append(s, "errorMountsResolutionCwd")
	}
	if (flags & api.EventErrorPathComponents) != 0 {
		s = append(s, "errorPathResolutionCwd")
	}
	return s
}

func FilePathFlagsToStr(flags uint32) string {
	var retval string

	if (flags & processapi.UnresolvedMountPoints) != 0 {
		retval += "unresolvedMountPoints"
	}
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		if len(retval) > 0 {
			retval += " "
		}
		retval += "unresolvedPathComponents"
	}
	return retval
}

func MarkUnresolvedPathComponents(path string, flags uint32) string {
	retval := path
	if (flags & processapi.UnresolvedMountPoints) != 0 {
		retval = "/[M]" + retval
	}
	if (flags & processapi.UnresolvedPathComponents) != 0 {
		retval = strings.ReplaceAll(retval, "&", "[P]")
	}
	return retval
}

func MarkUnresolvedPathComponentsCwd(path string, flags uint32) string {
	retval := path
	if (flags & api.EventErrorMountPoints) != 0 {
		retval = "/[M]" + retval
	}
	if (flags & api.EventErrorPathComponents) != 0 {
		retval = strings.ReplaceAll(retval, "&", "[P]")
	}
	return retval
}

func argsDecoderTrim(r rune) bool {
	if r == 0x00 {
		return true
	}
	return false
}

func SwapPath(path string) string {
	dirs := strings.Split(path, "/")
	for i := len(dirs)/2 - 1; i >= 0; i-- {
		opp := len(dirs) - 1 - i
		dirs[i], dirs[opp] = dirs[opp], dirs[i]
	}
	return strings.Join(dirs, "/")
}

func GenPath(path string) string {
	filePath := strings.TrimSuffix(SwapPath(path), "/")
	if len(filePath) > 0 && filePath[0] != '/' {
		filePath = "/" + filePath
	}
	return filePath
}

func ArgsDecoder(s string, flags uint32) (string, string) {
	var b []byte
	var cwd string
	var hasCWD int
	args := ""

	b = append(b, 0x00)
	argTokens := bytes.Split(bytes.TrimRightFunc([]byte(s), argsDecoderTrim), b)
	flagsOR := ((flags & api.EventNoCWDSupport) |
		(flags & api.EventErrorCWD) |
		(flags & api.EventRootCWD))
	if flagsOR == 0 {
		hasCWD = 1
	} else {
		hasCWD = 0
	}

	if (flags & api.EventNoCWDSupport) != 0 {
		cwd = ""
	} else if (flags & api.EventErrorCWD) != 0 {
		cwd = ""
	} else if (flags & api.EventRootCWD) != 0 {
		cwd = "/"
	} else if (flags & api.EventProcFS) != 0 {
		cwd = strings.TrimSpace(string(argTokens[len(argTokens)-1]))
	} else {
		cwd = "/" + SwapPath(string(argTokens[len(argTokens)-1]))
	}

	if len(argTokens) > hasCWD {
		for i, a := range argTokens {
			if i == len(argTokens)-hasCWD {
				continue
			}
			if strings.Contains(string(a), " ") {
				args = args + " \"" + string(a) + "\""
			} else {
				if args == "" {
					args = string(a)
				} else {
					args = args + " " + string(a)
				}
			}
		}
	}
	return args, cwd
}

func ObserverKfreeSkbPrinter(msg *kfreeapi.MsgKfreeSkb, log logrus.FieldLogger) {
	op := msg.Common.Op
	log.WithFields(logrus.Fields{
		"op":        ops.OpCode(op).String(),
		"ret":       msg.Calltrace.Ret,
		"calltrace": msg.Calltrace.Stack,
	}).Debug()
}

func KprobeAction(act uint64) fgs.KprobeAction {
	switch act {
	case tracingapi.ActionPost:
		return fgs.KprobeAction_KPROBE_ACTION_POST
	case tracingapi.ActionFollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_FOLLOWFD
	case tracingapi.ActionSigKill:
		return fgs.KprobeAction_KPROBE_ACTION_SIGKILL
	case tracingapi.ActionUnfollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_UNFOLLOWFD
	case tracingapi.ActionOverride:
		return fgs.KprobeAction_KPROBE_ACTION_OVERRIDE
	default:
		return fgs.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

var (
	HttpMultiMessage = uint32(0x1)
)

func HttpErrorFlags(flags uint32) []string {
	var s []string

	if (flags & IterErrorCodeRead) != 0 {
		s = append(s, "ChunkReadFailed")
	}
	if (flags & IterErrorCodeOverrun) != 0 {
		s = append(s, "ChunkTooLarge")
	}
	if (flags & HttpMultiMessage) != 0 {
		s = append(s, "MultiMessageEvent")
	}
	return s
}

func Signal(s uint32) string {
	if s == 0 {
		return ""
	}
	return unix.SignalName(syscall.Signal(s))
}
