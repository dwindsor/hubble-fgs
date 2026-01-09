// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package syslog

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/commands/fwactl/dataplane"
	fwadataplane "github.com/isovalent/hubble-fgs/pkg/dpu/dataplane"
	"github.com/isovalent/hubble-fgs/pkg/dpu/socket"
)

var syslogCmd = &cobra.Command{
	Use:          "syslog [file]",
	Short:        "Enable dataplane syslog using a JSON config file",
	Long:         "Enable dataplane syslog by sending a configuration JSON file to the dataplane.",
	SilenceUsage: true,
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing config filepath argument")
		}
		file, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open config file: %w", err)
		}
		cfg, err := readSyslogConfig(file)
		if err != nil {
			return fmt.Errorf("failed to read syslog config: %w", err)
		}
		if err := sendSyslogConfigToDataplane(cfg); err != nil {
			return fmt.Errorf("failed to enable syslog: %w", err)
		}
		return nil
	},
}

type Collector struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type SyslogConfig struct {
	SyslogEnabled  bool        `json:"log_enabled"`
	DataplaneLevel interface{} `json:"dataplane_level"`
	NpuIP          string      `json:"npu_ip"`
	NpuMAC         string      `json:"npu_mac"`
	Collector      []Collector `json:"collector"`
}

func readSyslogConfig(file *os.File) (*SyslogConfig, error) {
	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	var cfg SyslogConfig
	if err := json.Unmarshal(bytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config JSON: %w", err)
	}
	return &cfg, nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}

func getCurrentDsc0IP() (string, error) {
	cmd := exec.Command("ip", "addr", "show", "dev", "dsc0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	// Parse output for 'inet <ip>'
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "inet ") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "inet" && i+1 < len(fields) {
					ip := strings.Split(fields[i+1], "/")[0]
					return ip, nil
				}
			}
		}
	}
	return "", nil
}

func getCurrentRoutes() (map[string]bool, error) {
	cmd := exec.Command("ip", "route", "show", "dev", "dsc0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	routes := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			// first field is IP or subnet
			ip := fields[0]
			if strings.Contains(ip, "/") {
				ip = strings.Split(ip, "/")[0]
			}
			routes[ip] = true
		}
	}
	return routes, nil
}

func getCurrentARP() (map[string]bool, error) {
	cmd := exec.Command("arp", "-an")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	arps := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "dsc0") {
			// Format: ? (IP) at MAC [ether] on dsc0
			start := strings.Index(line, "(")
			end := strings.Index(line, ")")
			if start != -1 && end > start {
				ip := line[start+1 : end]
				arps[ip] = true
			}
		}
	}
	return arps, nil
}

func sendSyslogConfigToDataplane(cfg *SyslogConfig) error {
	currentIP, _ := getCurrentDsc0IP()
	newIP := cfg.NpuIP
	if newIP != "" && newIP != currentIP {
		// NPU IP is different: flush, assign, add all collector routes/ARP
		err := runCommand("ip", "addr", "flush", "dev", "dsc0")
		if err != nil {
			return fmt.Errorf("failed to flush dsc0: %w", err)
		}
		err = runCommand("ip", "addr", "add", newIP+"/32", "dev", "dsc0")
		if err != nil {
			return fmt.Errorf("failed to add NPU IP %s to dsc0: %w", newIP, err)
		}
		for _, collector := range cfg.Collector {
			err = runCommand("ip", "route", "add", collector.IP+"/32", "dev", "dsc0")
			if err != nil {
				return fmt.Errorf("failed to add route to collector IP %s via dsc0: %w", collector.IP, err)
			}
			if cfg.NpuMAC != "" {
				err = runCommand("arp", "-s", collector.IP, cfg.NpuMAC)
				if err != nil {
					return fmt.Errorf("failed to add ARP entry for collector IP %s: %w", collector.IP, err)
				}
			}
		}
		return nil
	}

	// NPU IP is same: only add/delete as needed
	routes, _ := getCurrentRoutes()
	arps, _ := getCurrentARP()
	collectorSet := make(map[string]bool)
	for _, collector := range cfg.Collector {
		collectorSet[collector.IP] = true
		if !routes[collector.IP] {
			err := runCommand("ip", "route", "add", collector.IP+"/32", "dev", "dsc0")
			if err != nil {
				return fmt.Errorf("failed to add route to collector IP %s via dsc0: %w", collector.IP, err)
			}
		}
		if cfg.NpuMAC != "" && !arps[collector.IP] {
			err := runCommand("arp", "-s", collector.IP, cfg.NpuMAC)
			if err != nil {
				return fmt.Errorf("failed to add ARP entry for collector IP %s: %w", collector.IP, err)
			}
		}
	}
	// Remove stale routes/ARP
	for ip := range arps {
		if !collectorSet[ip] {
			err := runCommand("arp", "-d", ip)
			if err != nil {
				return fmt.Errorf("failed to delete stale ARP %s: %w", ip, err)
			}
		}
	}

	for ip := range routes {
		if ip == newIP {
			continue
		}
		if !collectorSet[ip] {
			err := runCommand("ip", "route", "del", ip+"/32", "dev", "dsc0")
			if err != nil {
				return fmt.Errorf("failed to delete stale route %s: %w", ip, err)
			}
		}
	}

	// After all route/ARP logic, send config to dataplane socket
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal syslog config: %w", err)
	}

	dpsocket := socket.NewDataplaneSocket(dataplane.API_PATH, fwadataplane.UDS_TIMEOUT*time.Second)
	err = dpsocket.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to dataplane: %w", err)
	}
	defer dpsocket.Close()
	msg := &socket.ControlMessage{
		Command: fwadataplane.Dataplane_LogConfig,
		Type:    socket.DATAPLANE,
		Data:    data,
	}
	if err := dpsocket.Send(msg); err != nil {
		return fmt.Errorf("failed to send syslog config: %w", err)
	}
	rc, err := dpsocket.Receive()
	if err != nil {
		return fmt.Errorf("failed to receive syslog config response: %w", err)
	}
	_ = rc
	return nil
}

func init() {
	// fwactl dataplane syslog syslog.json --dp0
	dataplane.DataplaneCmd.AddCommand(syslogCmd)
}
