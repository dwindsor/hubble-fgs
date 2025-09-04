package config

import (
	"strings"

	"github.com/spf13/viper"
)

const (
	ENV_TOKEN = "HYPERSHIELD_TOKEN"
)

type Config struct {
	path string
	file *viper.Viper

	Env        Environment
	Controller Controller
	Agent      Agent
	Dataplane  Dataplane
}

type Environment struct {
	// Local paths
	TokenPath        string // Token path for storing and loading auth tokens
	MountDir         string // Host mount directory if running in a container
	BinaryDir        string // Hypershield binary directory path, acts as the root directory for service management
	DataplaneService string // Dataplane service symlink name
	DataplaneDir     string // Dataplane root directory, acts as the root directory for dataplane versions
	DataplaneBinary  string // Path to dataplane binary from a dataplane version directory
	ConfigureScript  string // Path to configure script from a dataplane version directory
	TempDir          string // Temporary directory path
}

type Controller struct {
	Debug   bool   // Debug mode
	Agw     string // DPU connects to the AGW service
	agwPort int
}

type Agent struct {
	AgentId           string // Agent ID
	TenantId          string // Tenant ID
	KeepAliveInterval int    // Time between keep alive messages
	DataplaneType     string // Dataplane type (dual or inline)
	LoggerConfigPath  string // Logger config file path
	LoggerServicePath string // Logger service path
}

type Dataplane struct {
	ServicePath string // Dataplane service path
	CpaSockFile string // CPA unix socket path (for CPA APIs)
	CliSockFile string // Fwactl unix socket path (for fwactl cli commands)
	PolicyPath  string // Policy file path
}

// Init tries to read the config file at path.
// If the file does not exist, it will create a new one with default values.
// It will return false if the file existed and true if it was created.
// If there is an error (except for file not found), it will return the error.
func (c *Config) Init(path string) (bool, error) {
	c.path = path
	c.file = viper.New()

	// Reading configuration file
	c.file.SetConfigFile(c.path)
	c.file.SetConfigType("json")
	var created bool
	if c.file == nil {
		created = true
	}

	// Setting defaults
	c.setDefaults()

	// Reading config to overwrite defaults
	err := c.read()
	if err != nil {
		return created, err
	}

	// Controller URL is usually found in the token, but since we are skipping auth, we need to set it here
	c.Controller.Agw = c.file.GetString("control_plane.controller_agw")
	c.Controller.agwPort = c.file.GetInt("control_plane.controller_agw_port")

	// Reading config to overwrite defaults
	err = c.read()
	if err != nil {
		return created, err
	}

	return created, nil
}

// Saving the config to file and then rereading it to update the values
func (c *Config) Reload() error {
	err := c.Save()
	if err != nil {
		return err
	}
	err = c.Update()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) Update() error {
	// Reading config to update values
	err := c.read()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) Save() error {
	// Checking if viper config was set
	if c.file == nil {
		return viper.ConfigFileNotFoundError{}
	}

	err := c.setValues()
	if err != nil {
		return err
	}

	// Writing config changes to file
	err = c.file.WriteConfig()
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) SavePath(path string) error {
	// Checking if viper config was set
	if c.file == nil {
		return viper.ConfigFileNotFoundError{}
	}

	err := c.setValues()
	if err != nil {
		return err
	}

	// Writing config changes to file
	err = c.file.WriteConfigAs(path)
	if err != nil {
		return err
	}
	return nil
}

func (c *Config) read() error {
	// Reading config
	err := c.file.ReadInConfig()
	if err != nil {
		return err
	}

	// Trimming AGW url if necessary
	c.Controller.Agw = strings.TrimPrefix(c.Controller.Agw, "https://")
	c.Controller.Agw = strings.TrimPrefix(c.Controller.Agw, "http://")

	// Controller
	c.Controller.Debug = c.file.GetBool("control_plane.debug")

	// Agent
	c.Agent.AgentId = c.file.GetString("control_plane.agent_id")
	c.Agent.TenantId = c.file.GetString("control_plane.tenant_id")
	c.Agent.KeepAliveInterval = c.file.GetInt("control_plane.keepalive_interval")
	c.Agent.LoggerConfigPath = c.file.GetString("control_plane.logger_config_path")
	c.Agent.LoggerServicePath = c.file.GetString("control_plane.logger_service_path")

	// Dataplanes
	c.Dataplane = Dataplane{
		ServicePath: c.file.GetString("dataplane0.service_path"),
		CpaSockFile: c.file.GetString("dataplane0.cpa_sockfile"),
		CliSockFile: c.file.GetString("dataplane0.cli_sockfile"),
		PolicyPath:  c.file.GetString("dataplane0.policy_path"),
	}
	return nil
}

func (c *Config) setValues() error {
	// Local paths
	c.file.Set("control_plane.dataplane_service", c.Env.DataplaneService)
	c.file.Set("control_plane.dataplane_dir", c.Env.DataplaneDir)
	c.file.Set("control_plane.dataplane_binary", c.Env.DataplaneBinary)
	c.file.Set("control_plane.configure_script", c.Env.ConfigureScript)
	c.file.Set("control_plane.temp_dir", c.Env.TempDir)

	// Controller
	c.file.Set("control_plane.debug", c.Controller.Debug)
	c.file.Set("control_plane.controller_agw", c.Controller.Agw)
	c.file.Set("control_plane.controller_port", c.Controller.agwPort)

	// Agent
	c.file.Set("control_plane.keepalive_interval", c.Agent.KeepAliveInterval)

	// Dataplanes
	c.file.Set("dataplane.cli_sockfile", c.Dataplane.CliSockFile)

	return nil
}

func (c *Config) setDefaults() {
	c.file.SetDefault("control_plane.debug", false)
	c.file.SetDefault("control_plane.agw_port", 8080)
	c.file.SetDefault("control_plane.keepalive_interval", 30)
	c.file.SetDefault("control_plane.logger_config_path", "/opt/cisco/daf/etc/daflogger.yaml")
	c.file.SetDefault("control_plane.logger_service_path", "/opt/cisco/daf/var/s6/services/logger")
	c.file.SetDefault("dataplane.service_path", "/opt/cisco/daf/var/s6/services/dp0")
	c.file.SetDefault("dataplane.policy_path", "/opt/cisco/daf/etc/dp0-policy.json")
	// TODO:
}
