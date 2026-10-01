// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein, and the intellectual and technical
// concepts contained herein, are proprietary to Isovalent Inc. and its suppliers.

// Package java installs Java class redefinitions through the JVM Attach API.
package java

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	api "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/pkg/javaattach"
)

const (
	sensorName      = "java"
	targetStageDir  = "/run/tetragon-java-patch"
	manifestMagic   = "TGJVP1\x00"
	maxClassFile    = 16 << 20
	maxPatchClasses = 32
)

type javaSensor struct {
	*sensors.Sensor
	executables []string
	argsContain []string
	patches     []api.JavaClassPatch
	targets     []processIdentity
	manifests   map[int]manifestPair
}

type manifestPair struct {
	dirHost, dirTarget, agentTarget string
	applyTarget, revertTarget       string
}

type processIdentity struct {
	pid        int
	executable string
	startTicks uint64
}

func (s *javaSensor) PolicyHandler(policy tracingpolicy.TracingPolicy, filterID policyfilter.PolicyID) (sensors.SensorIface, error) {
	if filterID != policyfilter.NoFilterID {
		return nil, errors.New("java sensor does not implement policy filtering")
	}
	spec := policy.TpSpec().Java
	if spec == nil {
		return nil, nil
	}
	if err := validate(spec); err != nil {
		return nil, err
	}
	return &javaSensor{
		Sensor:      &sensors.Sensor{Name: sensorName, Policy: policy.TpName(), Namespace: policy.TpNamespace()},
		executables: append([]string(nil), spec.Executables...),
		argsContain: append([]string(nil), spec.ProcessArgsContains...),
		patches:     spec.Patches,
	}, nil
}

func validate(spec *api.JavaPolicySpec) error {
	if len(spec.Executables) == 0 {
		return errors.New("java.executables must name at least one exact Java executable path")
	}
	for _, executable := range spec.Executables {
		if !filepath.IsAbs(executable) || strings.ContainsRune(executable, '\x00') {
			return fmt.Errorf("java executable %q must be an absolute path", executable)
		}
	}
	for _, token := range spec.ProcessArgsContains {
		if strings.TrimSpace(token) == "" || strings.ContainsRune(token, '\x00') {
			return errors.New("java.processArgsContains entries must be non-empty argument fragments")
		}
	}
	if len(spec.Patches) == 0 || len(spec.Patches) > maxPatchClasses {
		return fmt.Errorf("java.patches must contain between 1 and %d classes", maxPatchClasses)
	}
	seen := make(map[string]bool, len(spec.Patches))
	for i, patch := range spec.Patches {
		if !validSignature(patch.Signature) {
			return fmt.Errorf("java.patches[%d].signature must be a JVM object signature", i)
		}
		if seen[patch.Signature] {
			return fmt.Errorf("duplicate Java class signature %q", patch.Signature)
		}
		seen[patch.Signature] = true
		if len(patch.Replacement) == 0 || len(patch.Replacement) > maxClassFile {
			return fmt.Errorf("java.patches[%d].replacement must be a class file up to %d bytes", i, maxClassFile)
		}
		if len(patch.Rollback) == 0 || len(patch.Rollback) > maxClassFile {
			return fmt.Errorf("java.patches[%d].rollback must be a class file up to %d bytes", i, maxClassFile)
		}
		if !bytes.HasPrefix(patch.Replacement, []byte{0xca, 0xfe, 0xba, 0xbe}) || !bytes.HasPrefix(patch.Rollback, []byte{0xca, 0xfe, 0xba, 0xbe}) {
			return fmt.Errorf("java.patches[%d] contains data without a Java class-file header", i)
		}
	}
	return nil
}

func validSignature(sig string) bool {
	if len(sig) < 3 || sig[0] != 'L' || sig[len(sig)-1] != ';' {
		return false
	}
	return !strings.ContainsAny(sig[1:len(sig)-1], ".;[\x00")
}

func manifest(patches []api.JavaClassPatch, rollback bool) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(manifestMagic)
	if err := binary.Write(&b, binary.BigEndian, uint32(len(patches))); err != nil {
		return nil, err
	}
	for _, p := range patches {
		data := p.Replacement
		if rollback {
			data = p.Rollback
		}
		if len(p.Signature) > 0xffff || uint64(len(data)) > uint64(maxClassFile) {
			return nil, fmt.Errorf("class patch %q exceeds manifest limits", p.Signature)
		}
		if err := binary.Write(&b, binary.BigEndian, uint16(len(p.Signature))); err != nil {
			return nil, err
		}
		if err := binary.Write(&b, binary.BigEndian, uint32(len(data))); err != nil {
			return nil, err
		}
		b.WriteString(p.Signature)
		b.Write(data)
	}
	return b.Bytes(), nil
}

func (s *javaSensor) Load(_ string) error {
	if s.Loaded {
		return fmt.Errorf("java sensor %s is already loaded", s.Name)
	}
	apply, err := manifest(s.patches, false)
	if err != nil {
		return err
	}
	revert, err := manifest(s.patches, true)
	if err != nil {
		return err
	}
	pids, err := matchingPIDs(s.executables, s.argsContain)
	if err != nil {
		return err
	}
	if len(pids) == 0 {
		return errors.New("java policy found no running JVM with a configured executable")
	}
	s.manifests = make(map[int]manifestPair, len(pids))
	for _, target := range pids {
		pid := target.pid
		paths, err := stageProcessFiles(target, apply, revert)
		if err != nil {
			s.removeManifests()
			return fmt.Errorf("stage patch for JVM %d: %w", pid, err)
		}
		s.manifests[pid] = paths
		s.targets = append(s.targets, target)
		if err := javaattach.LoadNativeAgent(pid, paths.agentTarget, paths.applyTarget); err != nil {
			rollbackErr := s.rollbackTargets(s.targets)
			if rollbackErr == nil {
				s.targets = nil
				s.removeManifests()
			} else {
				// Retain rollback manifests and loaded state so the normal sensor
				// destroy path can retry restoration instead of orphaning a patch.
				s.Loaded = true
			}
			return errors.Join(fmt.Errorf("apply Java patch to pid %d: %w", pid, err), rollbackErr)
		}
		for _, patch := range s.patches {
			logger.GetLogger().Info("Java class redefined through JVM Attach", "pid", pid, "class", patch.Signature, "policy", s.Policy)
		}
	}
	s.Loaded = true
	return nil
}

func matchingPIDs(executables, argsContain []string) ([]processIdentity, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan /proc for JVMs: %w", err)
	}
	wanted := make(map[string]bool, len(executables))
	for _, path := range executables {
		wanted[filepath.Clean(path)] = true
	}
	var pids []processIdentity
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 {
			continue
		}
		path, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		path = strings.TrimSuffix(path, " (deleted)")
		if wanted[filepath.Clean(path)] {
			if len(argsContain) != 0 {
				cmdline, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
				if err != nil || !containsAllArgTokens(cmdline, argsContain) {
					continue
				}
			}
			start, err := processStartTicks(pid)
			if err != nil {
				continue
			}
			pids = append(pids, processIdentity{pid: pid, executable: filepath.Clean(path), startTicks: start})
		}
	}
	return pids, nil
}

func containsAllArgTokens(cmdline []byte, wanted []string) bool {
	if len(cmdline) == 0 {
		return false
	}
	args := bytes.Split(cmdline, []byte{0})
	for _, token := range wanted {
		if token == "" || strings.ContainsRune(token, '\x00') {
			return false
		}
		found := false
		for _, arg := range args {
			if bytes.Contains(arg, []byte(token)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func stageProcessFiles(target processIdentity, apply, revert []byte) (manifestPair, error) {
	pid := target.pid
	procPath := filepath.Join("/proc", strconv.Itoa(pid))
	procInfo, err := os.Stat(procPath)
	if err != nil {
		return manifestPair{}, err
	}
	owner, ok := procInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return manifestPair{}, errors.New("cannot determine JVM owner for staged patch")
	}
	procRoot := filepath.Join(procPath, "root")
	baseHost := filepath.Join(procRoot, strings.TrimPrefix(targetStageDir, "/"))
	if err := os.Mkdir(baseHost, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return manifestPair{}, fmt.Errorf("create JVM namespace staging directory: %w", err)
	}
	if err := ensureStageParent(baseHost); err != nil {
		return manifestPair{}, err
	}
	dirHost, err := os.MkdirTemp(baseHost, fmt.Sprintf("%d-%d-", pid, target.startTicks))
	if err != nil {
		return manifestPair{}, err
	}
	if err := os.Chown(dirHost, int(owner.Uid), int(owner.Gid)); err != nil {
		os.RemoveAll(dirHost)
		return manifestPair{}, err
	}
	if err := os.Chmod(dirHost, 0700); err != nil {
		os.RemoveAll(dirHost)
		return manifestPair{}, err
	}
	dirTarget := strings.TrimPrefix(dirHost, procRoot)
	paths := manifestPair{dirHost: dirHost, dirTarget: dirTarget, agentTarget: filepath.Join(dirTarget, "agent.so")}
	patchAgentPath := filepath.Join(option.Config.HubbleLib, "libtetragon-jvm-patch.so")
	if err := copyOwned(patchAgentPath, filepath.Join(dirHost, "agent.so"), int(owner.Uid), int(owner.Gid), 0500); err != nil {
		os.RemoveAll(dirHost)
		return manifestPair{}, fmt.Errorf("copy native JVMTI library into JVM namespace: %w", err)
	}
	paths.applyTarget = filepath.Join(dirTarget, "apply.manifest")
	paths.revertTarget = filepath.Join(dirTarget, "rollback.manifest")
	if err := writeOwned(filepath.Join(dirHost, "apply.manifest"), apply, int(owner.Uid), int(owner.Gid)); err != nil {
		os.RemoveAll(dirHost)
		return manifestPair{}, err
	}
	if err := writeOwned(filepath.Join(dirHost, "rollback.manifest"), revert, int(owner.Uid), int(owner.Gid)); err != nil {
		os.RemoveAll(dirHost)
		return manifestPair{}, err
	}
	return paths, nil
}

func ensureStageParent(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink != 0 || owner.Uid != 0 || !info.IsDir() {
		return errors.New("JVM namespace staging directory is not a root-owned directory")
	}
	// A stale root-owned directory with mode 0700 blocks the target JVM user
	// from loading the library staged below it. Keep this parent traversable;
	// each per-process child remains private (0700).
	if err := os.Chmod(path, 0755); err != nil {
		return fmt.Errorf("set JVM namespace staging directory mode: %w", err)
	}
	return nil
}

func copyOwned(src, dst string, uid, gid int, mode os.FileMode) error {
	input, err := os.Open(src)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		os.Remove(dst)
		return err
	}
	if err := output.Chown(uid, gid); err != nil {
		output.Close()
		os.Remove(dst)
		return err
	}
	if err := output.Chmod(mode); err != nil {
		output.Close()
		os.Remove(dst)
		return err
	}
	return output.Close()
}

func writeOwned(path string, data []byte, uid, gid int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chown(uid, gid); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

func processStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, err
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 {
		return 0, errors.New("invalid /proc stat command field")
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	// The remaining fields start at field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0, errors.New("truncated /proc stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func readProcessIdentity(pid int) (processIdentity, error) {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	executable, err := os.Readlink(filepath.Join(base, "exe"))
	if err != nil {
		return processIdentity{}, err
	}
	executable = filepath.Clean(strings.TrimSuffix(executable, " (deleted)"))
	startTicks, err := processStartTicks(pid)
	if err != nil {
		return processIdentity{}, err
	}
	return processIdentity{pid: pid, executable: executable, startTicks: startTicks}, nil
}

func (s *javaSensor) rollbackTargets(targets []processIdentity) error {
	var errs []error
	for i := len(targets) - 1; i >= 0; i-- {
		target := targets[i]
		pid := target.pid
		current, err := readProcessIdentity(pid)
		if err != nil {
			continue
		}
		if current.startTicks != target.startTicks || current.executable != target.executable {
			// PID was reused. Never send the rollback payload to another process.
			continue
		}
		paths := s.manifests[pid]
		if paths.revertTarget == "" {
			continue
		}
		if err := javaattach.LoadNativeAgent(pid, paths.agentTarget, paths.revertTarget); err != nil {
			errs = append(errs, fmt.Errorf("restore Java class definitions in pid %d: %w", pid, err))
		} else {
			for _, patch := range s.patches {
				logger.GetLogger().Info("Java class restored through JVM Attach", "pid", pid, "class", patch.Signature, "policy", s.Policy)
			}
		}
	}
	return errors.Join(errs...)
}

func (s *javaSensor) Unload(unpin bool) error {
	if !s.Loaded {
		return fmt.Errorf("unload of Java sensor %s failed: sensor not loaded", s.Name)
	}
	err := s.rollbackTargets(s.targets)
	if err == nil {
		s.targets = nil
		s.Loaded = false
		s.removeManifests()
	}
	return err
}

func (s *javaSensor) Destroy(unpin bool) error {
	if s.Destroyed {
		return nil
	}
	var err error
	if s.Loaded {
		err = s.Unload(unpin)
	}
	if err == nil {
		s.Destroyed = true
	}
	return err
}

func (s *javaSensor) removeManifests() {
	for _, pair := range s.manifests {
		_ = os.RemoveAll(pair.dirHost)
	}
	s.manifests = nil
}

func init() {
	instance := &javaSensor{Sensor: &sensors.Sensor{Name: sensorName}}
	sensors.RegisterPolicyHandlerAtInit(sensorName, instance)
}
