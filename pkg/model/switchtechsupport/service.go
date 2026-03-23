// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchtechsupport

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/isovalent/hubble-fgs/pkg/agw"
	"github.com/isovalent/hubble-fgs/pkg/ipc"
)

// DPU Tech Support Constants
const (
	// Paths
	DefaultTmpDir      = "/tmp/dpu_tech_support"
	DefaultArchivePath = "/iox_data/dpu_tech_support.tgz"
	DPULogBasePath     = "/var/log/pensando"
	DPUCoreBasePath    = "/data/core"
	SystemProcPath     = "/proc"
	SystemSysPath      = "/sys"

	// File patterns
	DPUAppLogFile    = "dp-app.log"
	DPUFwaLogFile    = "fwa.log"
	DPUAppLogPattern = "dp-app.log.*.gz"
	DPUFwaLogPattern = "fwa.log.*.gz"
	DPUCorePattern   = "core.*.tar"

	// Default credentials
	DefaultDPUUser     = "root"
	DefaultDPUPassword = "pen123" // Should be configurable

	// Validation limits
	MinPasswordLength     = 3
	MaxPasswordLength     = 64
	MaxFilePathLength     = 255
	MaxCommandLength      = 512
	MaxDirModePermissions = 0755
	MaxOutputLines        = 10000
	MaxProcessTimeout     = 300 // 5 minutes in seconds
	MaxConcurrentDPUs     = 4   // Maximum parallel DPU operations
	DefaultSemaphoreSize  = 5   // Default semaphore size for concurrency control

	// SSH options
	SSHStrictHostKeyChecking = "StrictHostKeyChecking=no"
	SSHUserKnownHostsFile    = "UserKnownHostsFile=/dev/null"
	SSHLogLevel              = "LogLevel=ERROR"
)

// DPUInfo represents information about a DPU
type DPUInfo struct {
	IP       string
	User     string
	Password string
}

// DPUCollectionResult represents the result of collecting from a single DPU
type DPUCollectionResult struct {
	DPUIP     string
	Success   bool
	FileCount int
	Error     string
}

// Service provides tech support collection functionality
type Service struct {
	agwAgent *agw.AgentGateway
}

// NewService creates a new tech support service instance
func NewService(agwAgent *agw.AgentGateway) *Service {
	return &Service{
		agwAgent: agwAgent,
	}
}

// CollectDpuTechSupport collects technical support data from DPUs
func (s *Service) CollectDpuTechSupport(ctx context.Context, includeCores bool) ipc.ReturnCode {
	var result strings.Builder

	// Validate context
	if ctx == nil {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       "Invalid context provided",
		}
	}

	if s.agwAgent == nil {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       "Invalid AGW agent provided",
		}
	}

	result.WriteString("Starting DPU tech support collection...\n")

	// Get list of DPUs from AGW
	dpus := s.getDpuList(ctx)

	if len(dpus) == 0 {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       result.String() + "No DPUs found or unable to retrieve DPU list",
		}
	}

	// list the DPUs
	for i, dpu := range dpus {
		fmt.Fprintf(&result, "DPU %d: IP=%s\n", i+1, dpu.IP)
	}

	// Create temporary directory
	tmpDir := DefaultTmpDir
	sanitizedTmpDir, err := s.sanitizeFilePath(tmpDir)
	if err != nil {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       result.String() + fmt.Sprintf("Invalid temporary directory path: %v", err),
		}
	}

	os.RemoveAll(sanitizedTmpDir)
	if err := os.MkdirAll(sanitizedTmpDir, MaxDirModePermissions); err != nil {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       result.String() + fmt.Sprintf("Failed to create temp directory: %v", err),
		}
	}

	// Collect files from all DPUs concurrently
	results := s.collectFromDPUsConcurrently(ctx, dpus, sanitizedTmpDir, includeCores)

	collectedFiles := 0
	failedDpus := []string{}
	for _, res := range results {
		if res.Success {
			collectedFiles += res.FileCount
			fmt.Fprintf(&result, "Successfully collected %d files from DPU %s\n", res.FileCount, res.DPUIP)
		} else {
			failedDpus = append(failedDpus, res.DPUIP)
			fmt.Fprintf(&result, "Failed to collect from DPU %s: %s\n", res.DPUIP, res.Error)
		}
	}

	// Summary
	result.WriteString("\n=== Collection Summary ===\n")
	fmt.Fprintf(&result, "Total DPUs processed: %d\n", len(dpus))
	fmt.Fprintf(&result, "Successful collections: %d\n", len(dpus)-len(failedDpus))
	fmt.Fprintf(&result, "Failed collections: %d\n", len(failedDpus))
	fmt.Fprintf(&result, "Total files collected: %d\n", collectedFiles)

	if len(failedDpus) > 0 {
		fmt.Fprintf(&result, "Failed DPUs: %s\n", strings.Join(failedDpus, ", "))
	}

	// Create archive
	archivePath := DefaultArchivePath
	if err := s.createTarGzArchive(sanitizedTmpDir, archivePath); err != nil {
		return ipc.ReturnCode{
			ReturnCode: "fail",
			Data:       result.String() + fmt.Sprintf("Failed to create archive: %v", err),
		}
	}
	fmt.Fprintf(&result, "Archive created: %s\n", archivePath)

	// Clean up temporary directory
	os.RemoveAll(sanitizedTmpDir)

	return ipc.ReturnCode{
		ReturnCode: "ok",
		Data:       result.String(),
	}
}

// getDpuList retrieves the list of DPUs from the AGW system
func (s *Service) getDpuList(ctx context.Context) []DPUInfo {
	// Call ShowDpu directly instead of making another IPC call
	dpuData := s.agwAgent.ShowDpu(ctx, ipc.MessageData{})

	if strings.TrimSpace(dpuData) == "" {
		return []DPUInfo{}
	}

	var dpus []DPUInfo
	lines := strings.Split(dpuData, "\n")

	// Skip the header line (first line) and parse each DPU entry
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if i == 0 || line == "" {
			continue // Skip header or empty lines
		}

		// Split by whitespace and extract the IP from the uid field (4th column)
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip := fields[3] // uid field contains the IP address

			// Validate IP address properly
			if err := s.validateIPAddress(ip); err != nil {
				continue
			}

			dpuInfo := DPUInfo{
				IP:       ip,
				User:     DefaultDPUUser,
				Password: DefaultDPUPassword, // Default password - should be configurable
			}

			// Validate DPU credentials
			if err := s.validateDPUCredentials(dpuInfo); err != nil {
				continue
			}

			dpus = append(dpus, dpuInfo)
		}
	}

	return dpus
}

// collectFromDPUsConcurrently processes multiple DPUs concurrently with rate limiting
func (s *Service) collectFromDPUsConcurrently(_ context.Context, dpus []DPUInfo, baseDir string, includeCores bool) []DPUCollectionResult {
	semaphore := make(chan struct{}, DefaultSemaphoreSize)
	var wg sync.WaitGroup
	results := make([]DPUCollectionResult, len(dpus))

	for i, dpu := range dpus {
		wg.Add(1)
		go func(idx int, d DPUInfo) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[idx] = s.collectFromDPU(d, baseDir, includeCores)
		}(i, dpu)
	}
	wg.Wait()

	return results
}

// collectFromDPU collects files from a single DPU
func (s *Service) collectFromDPU(dpu DPUInfo, baseDir string, includeCores bool) DPUCollectionResult {
	result := DPUCollectionResult{
		DPUIP:     dpu.IP,
		Success:   false,
		FileCount: 0,
		Error:     "",
	}

	// Create DPU directory
	dpuDir := filepath.Join(baseDir, fmt.Sprintf("dpu_%s", dpu.IP))
	if err := os.MkdirAll(dpuDir, MaxDirModePermissions); err != nil {
		result.Error = fmt.Sprintf("Failed to create directory: %v", err)
		return result
	}

	// Collect main log files
	logFiles := []string{
		filepath.Join(DPULogBasePath, DPUAppLogFile),
		filepath.Join(DPULogBasePath, DPUFwaLogFile),
	}

	collected := 0
	for _, logFile := range logFiles {
		localFile := filepath.Join(dpuDir, filepath.Base(logFile))
		if s.collectDPUFile(dpu, logFile, localFile) {
			collected++
		}
	}

	// Collect rotated logs
	rotatedPatterns := []string{
		filepath.Join(DPULogBasePath, DPUAppLogPattern),
		filepath.Join(DPULogBasePath, DPUFwaLogPattern),
	}

	for _, pattern := range rotatedPatterns {
		if err := s.validateFilePattern(pattern); err == nil {
			if files := s.collectDPUFilesPattern(dpu, pattern, dpuDir); files > 0 {
				collected += files
			}
		}
	}

	// Collect core dumps if requested
	if includeCores {
		corePattern := filepath.Join(DPUCoreBasePath, DPUCorePattern)
		if err := s.validateFilePattern(corePattern); err == nil {
			if files := s.collectDPUFilesPattern(dpu, corePattern, dpuDir); files > 0 {
				collected += files
			}
		}
	}

	result.Success = collected > 0
	result.FileCount = collected
	if !result.Success {
		result.Error = "No files collected"
	}

	return result
}

// Helper methods
func (d *DPUInfo) executeSSHCommand(command string) *exec.Cmd {
	return exec.Command("sshpass", "-p", d.Password, "ssh",
		"-o", SSHStrictHostKeyChecking,
		"-o", SSHUserKnownHostsFile,
		"-o", SSHLogLevel,
		fmt.Sprintf("%s@%s", d.User, d.IP), command)
}

func (d *DPUInfo) executeSCPCommand(remotePath, localPath string) *exec.Cmd {
	return exec.Command("sshpass", "-p", d.Password, "scp",
		"-o", SSHStrictHostKeyChecking,
		"-o", SSHUserKnownHostsFile,
		"-o", SSHLogLevel,
		fmt.Sprintf("%s@%s:%s", d.User, d.IP, remotePath),
		localPath)
}

func (s *Service) collectDPUFile(dpu DPUInfo, remoteFile, localFile string) bool {
	sanitizedRemote, err := s.sanitizeFilePath(remoteFile)
	if err != nil {
		return false
	}

	sanitizedLocal, err := s.sanitizeFilePath(localFile)
	if err != nil {
		return false
	}

	localDir := filepath.Dir(sanitizedLocal)
	if err := os.MkdirAll(localDir, MaxDirModePermissions); err != nil {
		return false
	}

	cmd := dpu.executeSCPCommand(sanitizedRemote, sanitizedLocal)
	if err := cmd.Run(); err != nil {
		return false
	}

	if stat, err := os.Stat(sanitizedLocal); err == nil && stat.Size() > 0 {
		return true
	}

	return false
}

func (s *Service) collectDPUFilesPattern(dpu DPUInfo, pattern, targetDir string) int {
	collected := 0

	sanitizedTargetDir, err := s.sanitizeFilePath(targetDir)
	if err != nil {
		return 0
	}

	if err := s.validateFilePattern(pattern); err != nil {
		return 0
	}

	cmd := fmt.Sprintf("ls %s 2>/dev/null", pattern)
	out, err := dpu.executeSSHCommand(cmd).Output()
	if err != nil {
		return 0
	}

	files := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file != "" && !strings.Contains(file, "No such file") {
			if _, err := s.sanitizeFilePath(file); err != nil {
				continue
			}

			localFile := filepath.Join(sanitizedTargetDir, filepath.Base(file))
			if s.collectDPUFile(dpu, file, localFile) {
				collected++
			}
		}
	}

	return collected
}

func (s *Service) createTarGzArchive(sourceDir, archivePath string) error {
	cmd := exec.Command("tar", "czf", archivePath, "-C", filepath.Dir(sourceDir), filepath.Base(sourceDir))
	return cmd.Run()
}

func (s *Service) sanitizeFilePath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty path not allowed")
	}

	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path traversal detected in: %s", path)
	}

	if strings.HasPrefix(path, SystemProcPath+"/") || strings.HasPrefix(path, SystemSysPath+"/") {
		return "", fmt.Errorf("access to system paths not allowed: %s", path)
	}

	cleanPath := filepath.Clean(path)

	if !strings.HasPrefix(path, "/") {
		cleanPath = filepath.Join("/tmp", cleanPath)
	}

	return cleanPath, nil
}

func (s *Service) validateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("empty IP address")
	}

	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address format: %s", ip)
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP.IsLoopback() {
		return fmt.Errorf("loopback IP address not allowed: %s", ip)
	}

	return nil
}

func (s *Service) validateFilePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("empty file pattern")
	}

	if strings.Contains(pattern, "..") {
		return fmt.Errorf("path traversal detected in pattern: %s", pattern)
	}

	dangerousChars := []string{";", "|", "&", "`", "$", "(", ")"}
	for _, char := range dangerousChars {
		if strings.Contains(pattern, char) {
			return fmt.Errorf("potentially dangerous character '%s' in pattern: %s", char, pattern)
		}
	}

	logPattern := regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+\*?\.?[a-zA-Z0-9*]*$`)
	if !logPattern.MatchString(pattern) {
		return fmt.Errorf("invalid file pattern format: %s", pattern)
	}

	return nil
}

func (s *Service) validateDPUCredentials(dpu DPUInfo) error {
	if err := s.validateIPAddress(dpu.IP); err != nil {
		return fmt.Errorf("invalid DPU IP: %w", err)
	}

	if dpu.User == "" {
		return fmt.Errorf("empty username for DPU %s", dpu.IP)
	}

	userPattern := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	if !userPattern.MatchString(dpu.User) {
		return fmt.Errorf("invalid username format for DPU %s: %s", dpu.IP, dpu.User)
	}

	if dpu.Password == "" {
		return fmt.Errorf("empty password for DPU %s", dpu.IP)
	}

	if len(dpu.Password) < MinPasswordLength || len(dpu.Password) > MaxPasswordLength {
		return fmt.Errorf("password length out of range for DPU %s", dpu.IP)
	}

	return nil
}
