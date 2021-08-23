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
package observer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
)

var (
	dockerIdSet = 0
)

func procDockerIdOffsetWriter(off int, btf bpf.BTF) error {
	if dockerIdSet != 0 {
		return nil
	}
	dockerIdSet = 1
	errInt := btf.AddEnum("fgs_args_proc", 1)
	if errInt < 0 {
		return fmt.Errorf("AddenumBtf failed %d", errInt)
	}
	errInt = btf.AddEnumValue("fgs_args_docker_off", off)
	if errInt < 0 {
		return fmt.Errorf("AddenumBtf enumValue failed value=%d error %d", off, errInt)
	}
	return nil
}

func procDockerIdOffsetDefault(btf bpf.BTF) error {
	return procDockerIdOffsetWriter(0, btf)
}

func procsDockerIdOffset(docker string) (string, int, error) {
	s := strings.Split(docker, "-")

	if len(s) == 1 {
		return s[0], 0, nil
	} else if len(s) > 1 {
		return s[1], len(s[0]) + 1, nil
	}

	return "", 0, fmt.Errorf("Docker string (%s) parse error", docker)
}

func procsFilename(args []byte) (string, string) {
	cmdArgs := bytes.Split(args, []byte{0x00})
	filename := string(cmdArgs[0])
	cmds := string(bytes.Join(cmdArgs[1:], []byte{0x00}))
	return cmds, filename
}

func procsFindDockerId(cgroups string) (string, int, error) {
	docker := strings.Split(cgroups, "\n")
	for _, s := range docker {
		if strings.Contains(s, "pids:") && (strings.Contains(s, "pods") || strings.Contains(s, "docker")) {
			dockerFields := strings.Split(s, "/")
			dockerString := dockerFields[len(dockerFields)-1]
			// Special case for syscont-cgroup-root installed by
			// sysbox nested containers. In this case set with
			// outermost container.
			if strings.Contains(dockerString, "syscont-cgroup-root") {
				if len(dockerFields) > 4 {
					dockerString = dockerFields[4]
				}
			}
			docker, i, err := procsDockerIdOffset(dockerString)
			// return first 31 chars to match BPF generated values.
			// If the string is less than 31 chars its not a docker
			// ID so skip it. For example docker.server will get here.
			if len(docker) > 30 {
				return docker[:31], i, err
			}
		}
	}
	return "", 0, nil
}

func procsDockerId(pid uint32) (string, int, error) {
	pidstr := fmt.Sprint(pid)
	cgroups, err := ioutil.ReadFile(filepath.Join(ProcFS, pidstr, "cgroup"))
	if err != nil {
		return "", 0, err
	}
	return procsFindDockerId(string(cgroups))
}
