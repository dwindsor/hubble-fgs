package observer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/covalentio/hubble-fgs/pkg/bpf"
)

var (
	dockerIdSet = 0
)

func procDockerIdOffsetWriter(off int, btf uintptr) error {
	if dockerIdSet != 0 {
		return nil
	}
	dockerIdSet = 1
	errInt := bpf.AddEnumBtf(btf, "fgs_args_proc", 1)
	if errInt < 0 {
		return fmt.Errorf("AddenumBtf failed %d", errInt)
	}
	errInt = bpf.AddEnumBtfValue(btf, "fgs_args_docker_off", off)
	if errInt < 0 {
		return fmt.Errorf("AddenumBtf enumValue failed value=%d error %d", off, errInt)
	}
	return nil
}

func procDockerIdOffsetDefault(btf uintptr) error {
	return procDockerIdOffsetWriter(0, btf)
}

func procsDockerIdOffset(docker string) (string, int, error) {
	s := strings.Split(docker, "-")

	if len(s) == 1 {
		return s[0], 0, nil
	} else if len(s) > 1 {
		return s[1], len(s[0]) + 1, nil
	}

	return "", 0, fmt.Errorf("Docker string (%s) parse error\n", docker)
}

func procsFilename(args []byte) (string, string) {
	cmdArgs := bytes.Split(args, []byte{0x00})
	filename := string(cmdArgs[0])
	cmds := string(bytes.Join(cmdArgs[1:], []byte{0x00}))
	return cmds, filename
}

func procsDockerId(pid uint32) (string, int, error) {
	pidstr := fmt.Sprint(pid)
	cgroups, err := ioutil.ReadFile(filepath.Join(ProcFS, pidstr, "cgroup"))
	if err != nil {
		return "", 0, err
	}
	docker := strings.Split(string(cgroups), "\n")
	for _, s := range docker {
		if strings.Contains(s, "pids:") && strings.Contains(s, "pods") {
			dockerFields := strings.Split(s, "/")
			dockerString := dockerFields[len(dockerFields)-1]
			return procsDockerIdOffset(dockerString)
		}
	}
	return "", 0, nil
}
