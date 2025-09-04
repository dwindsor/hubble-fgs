package config

import (
	"errors"
	"os"
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
	Dataplanes map[string]Dataplane
}

type Environment struct {
	// Build parameters
	SkipAuth    bool
	IsDpu       bool
	IsContainer bool

	// Cert paths
	ClientCa   string // Client CA cert path
	ClientCert string // Client cert path
	ClientKey  string // Client key path
	ServerCa   string // Server CA cert path
	ServerCert string // Server cert path
	ServerKey  string // Server key path

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
	Debug bool   // Debug mode
	Url   string // Well known controller url
}

type Agent struct {
	AgentId              string // Agent ID
	VerificationDuration int    // Verification duration for policy testing
	KeepAliveInterval    int    // Time between keep alive messages
}

type Dataplane struct {
	ServicePath string // Dataplane service path
	VppSockFile string // Vpp unix socket path (for VPP APIs)
	CpaSockFile string // CPA unix socket path (for CPA APIs)
	CliSockFile string // Fwactl unix socket path (for fwactl cli commands)
}

// Build time variables
var SkipAuth string
var IsDpu string

// Init tries to read the config file at path.
// If the file does not exist, it will create a new one with default values.
// It will return false if the file existed and true if it was created.
// If there is an error (except for file not found), it will return the error.
func (c *Config) Init(path string) (bool, error) {
	c.path = path
	c.file = viper.New()
	c.Dataplanes = make(map[string]Dataplane)

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

	// Setting build variables
	if SkipAuth == "true" {
		c.Env.SkipAuth = true
		// Controller URL is usually found in the token, but since we are skipping auth, we need to set it here
		c.Controller.Url = c.file.GetString("control_plane.controller_url")
	} else {
		c.Env.SkipAuth = false
	}
	if IsDpu == "true" {
		c.Env.IsDpu = true
		if !c.Env.SkipAuth {
			err := errors.New("IsDpu and SkipAuth mismatch")
			return created, err
		}
	} else {
		c.Env.IsDpu = false
	}

	// Checking if running in a container
	if hostPath, ok := os.LookupEnv("HOST_MOUNT_PATH"); ok {
		c.Env.IsContainer = true
		c.Env.MountDir = hostPath
	} else {
		c.Env.IsContainer = false
		c.Env.MountDir = ""
	}

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

	// Trimming controller url if necessary
	c.Controller.Url = strings.TrimPrefix(c.Controller.Url, "http://")
	c.Controller.Url = strings.TrimPrefix(c.Controller.Url, "https://")

	// Environment
	c.Env.TokenPath = c.file.GetString("control_plane.token_path")
	c.Env.ClientCa = c.file.GetString("control_plane.ca_cert")
	c.Env.ClientCert = c.file.GetString("control_plane.client_cert")
	c.Env.ClientKey = c.file.GetString("control_plane.client_key")

	// Controller
	c.Controller.Debug = c.file.GetBool("control_plane.debug")

	// Agent
	c.Agent.VerificationDuration = c.file.GetInt("control_plane.verification_duration")
	c.Agent.KeepAliveInterval = c.file.GetInt("control_plane.keepalive_interval")

	// Dataplanes
	c.Dataplanes["0"] = Dataplane{
		ServicePath: c.file.GetString("dataplane0.service_path"),
		VppSockFile: c.file.GetString("dataplane0.api_sockfile"),
		CpaSockFile: c.file.GetString("dataplane0.cpa_sockfile"),
		CliSockFile: c.file.GetString("dataplane0.cli_sockfile"),
	}

	return nil
}

func (c *Config) setValues() error {
	// Certs
	c.file.Set("control_plane.ca_cert", c.Env.ClientCa)
	c.file.Set("control_plane.client_cert", c.Env.ClientCert)
	c.file.Set("control_plane.client_key", c.Env.ClientKey)
	c.file.Set("control_plane.server_ca", c.Env.ServerCa)
	c.file.Set("control_plane.server_cert", c.Env.ServerCert)
	c.file.Set("control_plane.server_key", c.Env.ServerKey)

	// Local paths
	c.file.Set("control_plane.token_path", c.Env.TokenPath)
	c.file.Set("control_plane.binary_dir", c.Env.BinaryDir)
	c.file.Set("control_plane.dataplane_service", c.Env.DataplaneService)
	c.file.Set("control_plane.dataplane_dir", c.Env.DataplaneDir)
	c.file.Set("control_plane.dataplane_binary", c.Env.DataplaneBinary)
	c.file.Set("control_plane.configure_script", c.Env.ConfigureScript)
	c.file.Set("control_plane.temp_dir", c.Env.TempDir)

	// Controller
	c.file.Set("control_plane.debug", c.Controller.Debug)

	// Agent
	c.file.Set("control_plane.keepalive_interval", c.Agent.KeepAliveInterval)
	c.file.Set("control_plane.verification_duration", c.Agent.VerificationDuration)

	// Dataplanes
	c.file.Set("dataplane0.api_sockfile", c.Dataplanes["0"].VppSockFile)
	c.file.Set("dataplane0.cli_sockfile", c.Dataplanes["0"].CliSockFile)

	return nil
}

func (c *Config) setDefaults() {
	c.file.SetDefault("control_plane.debug", false)
	c.file.SetDefault("control_plane.keepalive_interval", 30)
	c.file.SetDefault("control_plane.verification_duration", 60)
	c.file.SetDefault("control_plane.token_path", "/opt/cisco/daf/etc/cpa_tokens")
	c.file.SetDefault("dataplane0.service_path", "/opt/cisco/daf/var/s6/services/dp0")
}
