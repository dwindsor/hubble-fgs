// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package exporter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config"
	flb "github.com/isovalent/hubble-fgs/pkg/dpu/exporter/fluentbit"
)

// Returns a newly created accelerated fluentbit exporter object
//
// Parameters:
//   - id: string
//   - configPath: string
func NewAcceleratedFluentbitExporter(id string, configPath string) *AcceleratedFluentbitExporter {
	return &AcceleratedFluentbitExporter{
		Fluentbit: &AcceleratedFluentbitExporterProcess{
			Id:         id,
			ConfigPath: configPath,
		},
	}
}

// -----------------------------------------------------------------------------
// Individual Exporter Implementation
// -----------------------------------------------------------------------------

type AcceleratedFluentbitExporterProcess struct {
	Id         string
	Version    string
	ConfigPath string
	Status     atomic.Bool

	NpuMac      string
	NpuIP       string
	NpuPortLow  uint32
	NpuPortHigh uint32

	Config flb.FluentBitConfig
}

func (fb *AcceleratedFluentbitExporterProcess) GetId() string {
	return fb.Id
}

func (fb *AcceleratedFluentbitExporterProcess) GetVersion() string {
	return fb.Version
}

func (fb *AcceleratedFluentbitExporterProcess) Start(_ context.Context) error {
	fb.Status.Store(true)
	return nil
}

func (fb *AcceleratedFluentbitExporterProcess) Stop(_ context.Context) error {
	fb.Status.Store(false)
	return nil
}

func (fb *AcceleratedFluentbitExporterProcess) UpdateConfig(config flb.FluentBitConfig) error {
	// Validating the config by marshaling it to yaml.
	configData, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	fb.Config = config

	// Writing the config to the config file
	err = os.WriteFile(fb.ConfigPath, configData, 0644)
	if err != nil {
		return err
	}

	// Restarting fluentbit and updating the arp/routes
	err = fb.UpdateOutputNetworking()
	if err != nil {
		return err
	}
	return nil
}

func (fb *AcceleratedFluentbitExporterProcess) UpdateOutputNetworking() error {
	// Stopping fluentbit while reconfiguring networking
	// Defering restart to ensure it is restarted even on error
	_, err := runCommand("sysmgrctl", "stop-service", "logger")
	if err != nil {
		return err
	}
	defer func() {
		runCommand("sysmgrctl", "start-service", "logger")
		time.Sleep(2 * time.Second) // Waiting for fluentbit to start up
	}()

	// Get the dsc0 link interface
	link, err := netlink.LinkByName("dsc0")
	if err != nil {
		return fmt.Errorf("failed to get dsc0 interface: %w", err)
	}

	// Getting the current routes for dsc0
	routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list routes for dsc0: %w", err)
	}

	routeMap := make(map[string]bool)
	for _, route := range routes {
		if route.Dst != nil {
			ip := route.Dst.IP.String()
			routeMap[ip] = true
		}
	}

	// Getting the current ARP/neighbor entries for dsc0
	neighbors, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("failed to list neighbors for dsc0: %w", err)
	}

	arpMap := make(map[string]bool)
	for _, neigh := range neighbors {
		if neigh.IP != nil {
			arpMap[neigh.IP.String()] = true
		}
	}

	// Setting routes and ARP entries for each output
	outputIps := make(map[string]bool)
	for _, output := range fb.Config.Pipeline.Outputs {
		if output.Properties["host"] == "" {
			continue
		}
		outputIps[output.Properties["host"]] = true // Deduplicate export ips
	}

	for ipStr := range outputIps {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}

		// Add route if it doesn't exist
		if !routeMap[ipStr] {
			route := &netlink.Route{
				Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, // /32 mask
				LinkIndex: link.Attrs().Index,
			}
			if err := netlink.RouteAdd(route); err != nil {
				return fmt.Errorf("failed to add route to collector IP %s via dsc0: %w", ipStr, err)
			}
		}

		// Add ARP entry if MAC is provided and entry doesn't exist
		if fb.NpuMac != "" && !arpMap[ipStr] {
			mac, err := net.ParseMAC(fb.NpuMac)
			if err != nil {
				return fmt.Errorf("invalid MAC address %s: %w", fb.NpuMac, err)
			}

			neigh := &netlink.Neigh{
				LinkIndex:    link.Attrs().Index,
				IP:           ip,
				HardwareAddr: mac,
				State:        netlink.NUD_PERMANENT,
			}
			if err := netlink.NeighAdd(neigh); err != nil {
				return fmt.Errorf("failed to add ARP entry for collector IP %s: %w", ipStr, err)
			}
		}
	}

	// Remove stale ARP entries
	for _, neigh := range neighbors {
		if neigh.IP == nil {
			continue
		}
		ipStr := neigh.IP.String()
		if ipStr == fb.NpuIP {
			continue
		}
		if !outputIps[ipStr] {
			if err := netlink.NeighDel(&neigh); err != nil {
				return fmt.Errorf("failed to delete stale ARP entry %s: %w", ipStr, err)
			}
		}
	}

	// Remove stale routes
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		ipStr := route.Dst.IP.String()
		if ipStr == fb.NpuIP {
			continue
		}
		if !outputIps[ipStr] {
			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete stale route %s: %w", ipStr, err)
			}
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Fluentbit Exporter Implementation
// -----------------------------------------------------------------------------

type AcceleratedFluentbitExporter struct {
	Fluentbit *AcceleratedFluentbitExporterProcess
}

func (fb *AcceleratedFluentbitExporter) Mode() ExporterType {
	return ACCELERATED_FLUENTBIT_EXPORTER
}

func (fb *AcceleratedFluentbitExporter) Version() string {
	return fb.Fluentbit.Version
}

func (fb *AcceleratedFluentbitExporter) RefreshConfig(oldCfg *v1alpha.ConfigObject, newCfg *v1alpha.ConfigObject) error {
	// Checking config object
	cfg := newCfg
	if newCfg == nil {
		cfg = oldCfg
	}
	if cfg == nil {
		return errors.New("nil config object in fluentbit exporter callback")
	}

	switch cfg.Type {
	case v1alpha.ConfigType_CONFIG_TYPE_DPU:
		if newCfg == nil {
			return nil // Doing nothing if the config is deleted
		}
		// Parsing out the dpu configuration
		dpuConfig := cfg.GetConfigDpu()
		fb.Fluentbit.NpuIP = dpuConfig.ServiceIp
		fb.Fluentbit.NpuMac = dpuConfig.ServiceMac
		fb.Fluentbit.NpuPortLow = dpuConfig.PortLow
		fb.Fluentbit.NpuPortHigh = dpuConfig.PortHigh
		return nil
	case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG, v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE, v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
		// Switching on config type
		var oldLogConfigs map[string]*v1alpha.LogConfig
		var newLogConfigs map[string]*v1alpha.LogConfig
		switch cfg.Type {
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_SYSLOG:
			if oldCfg != nil {
				oldLogConfigs = oldCfg.GetConfigLogSyslog().Configs
			}
			if newCfg != nil {
				newLogConfigs = newCfg.GetConfigLogSyslog().Configs
			}
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_TIMESCAPE:
			if oldCfg != nil {
				oldLogConfigs = oldCfg.GetConfigLogTimescape().Configs
			}
			if newCfg != nil {
				newLogConfigs = newCfg.GetConfigLogTimescape().Configs
			}
		case v1alpha.ConfigType_CONFIG_TYPE_LOG_SPLUNK:
			if oldCfg != nil {
				oldLogConfigs = oldCfg.GetConfigLogSplunk().Configs
			}
			if newCfg != nil {
				newLogConfigs = newCfg.GetConfigLogSplunk().Configs
			}
		}

		// Adding and removing the necessary log configs
		logConfigAdds, logConfigRemoves := config.DiffLogConfigMaps(oldLogConfigs, newLogConfigs)
		newConfig := fb.Fluentbit.Config
		var err error
		for id := range logConfigRemoves {
			newConfig = flb.RemoveLogConfig(newConfig, id)
		}
		for _, logConfig := range logConfigAdds {
			newConfig, err = flb.AddLogConfig(newConfig, cfg.Type, logConfig)
			if err != nil {
				logger.GetLogger().Error("failed to apply log export config", logfields.Error, err, "type", cfg.Type)
				return err
			}
		}

		// Updating the fluentbit config
		err = fb.Fluentbit.UpdateConfig(newConfig)
		if err != nil {
			return err
		}
		return nil
	default:
		return errors.New("invalid config type")
	}
}

func (fb *AcceleratedFluentbitExporter) Init(_ context.Context) error {
	// Setting the default config
	err := fb.Fluentbit.UpdateConfig(flb.DefaultConfig())
	if err != nil {
		return err
	}
	fb.Fluentbit.Config = flb.DefaultConfig()
	return nil
}

func (fb *AcceleratedFluentbitExporter) Connect(ctx context.Context, _ bool) error {
	// Initializing exporter
	err := fb.Init(ctx)
	if err != nil {
		return err
	}

	// Starting the exporter
	ctxTimeout, cancel := context.WithTimeout(ctx, TIMEOUT*time.Second)
	defer cancel()
	err = fb.Start(ctxTimeout)
	if err != nil {
		return err
	}
	return nil
}

func (fb *AcceleratedFluentbitExporter) Close(ctx context.Context) {
	fb.Stop(ctx)
}

func (fb *AcceleratedFluentbitExporter) Start(ctx context.Context) error {
	// Starting fluentbit exporter
	err := fb.Fluentbit.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to start accelerated fluentbit exporter", "id", fb.Fluentbit.Id)
		return err
	}

	return nil
}

func (fb *AcceleratedFluentbitExporter) Stop(ctx context.Context) error {
	// Stopping fluentbit exporter
	err := fb.Fluentbit.Stop(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to stop accelerated fluentbut exporter", "id", fb.Fluentbit.Id)
		return err
	}

	return nil
}

func (fb *AcceleratedFluentbitExporter) Restart(ctx context.Context) error {
	// Stopping and starting exporter
	err := fb.Stop(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to restart accelerated fluentbit exporter", "id", fb.Fluentbit.Id)
		return err
	}
	err = fb.Start(ctx)
	if err != nil {
		logger.GetLogger().Error("Failed to restart accelerated fluentbit exporter", "id", fb.Fluentbit.Id)
		return err
	}
	return nil
}

func (fb *AcceleratedFluentbitExporter) Status() bool {
	// Returning status of the fluentbit exporter
	return fb.Fluentbit.Status.Load()
}

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

// Runs the command and returns the combined stdout and stderr output
func runCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, string(output))
	}
	return string(output), nil
}
