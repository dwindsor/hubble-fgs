package config

import (
	"errors"
	"fmt"
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

	Env         Environment
	Controller  Controller
	Agent       Agent
	Dispatcher  Dispatcher
	Dataplanes  map[string]Dataplane
	GraphEngine GraphEngine
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
	TokenPath         string // Token path for storing and loading auth tokens
	MountDir          string // Host mount directory if running in a container
	BinaryDir         string // Hypershield binary directory path, acts as the root directory for service management
	DispatcherService string // Dispatcher service symlink name
	DispatcherDir     string // Dispatcher root directory, acts as the root directory for dispatcher versions
	DispatcherBinary  string // Path to dispatcher binary from a dispatcher version directory
	DataplaneService  string // Dataplane service symlink name
	DataplaneDir      string // Dataplane root directory, acts as the root directory for dataplane versions
	DataplaneBinary   string // Path to dataplane binary from a dataplane version directory
	ConfigureScript   string // Path to configure script from a dataplane version directory
	TempDir           string // Temporary directory path
}

type Controller struct {
	Debug         bool   // Debug mode
	Url           string // Well known controller url
	Swarm         string // Swarm service url (controller url with swarm port appended)
	swarmPort     int    // Swarm service port
	Deploy        string // Deploy service url (controller url with deploy port appended)
	deployPort    int    // Deploy service port
	Collector     string // Collector service url (controller url with collector port appended)
	collectorPort int    // Collector service port
}

type Agent struct {
	AgentId               string // Agent ID
	TenantId              string // Tenant ID
	SnapshotInterval      int    // Verification snapshot interval
	SnapshotCount         int    // Number of snapshots that need to pass for software verification to succeed
	VerificationDuration  int    // Verification duration for policy testing
	KeepAliveInterval     int    // Time between keep alive messages
	VerificationQueuePath string // Verification queue file path
	FsmStatePath          string // FSM state file path
	DataplaneType         string // Dataplane type (dual or inline)
	LoggerConfigPath      string // Logger config file path
	LoggerServicePath     string // Logger service path
}

type Dispatcher struct {
	ServicePath string // Dispatcher service path
	SockFile    string // Dispatcher unix socket path
	StateFile   string // Dataplane state file path
	CliSockFile string // Fwactl unix socket path (for fwactl cli commands)
}

type Dataplane struct {
	Mode        string // Dataplane mode (dual or inline)
	ServicePath string // Dataplane service path
	VppSockFile string // Vpp unix socket path (for VPP APIs)
	CpaSockFile string // CPA unix socket path (for CPA APIs)
	CliSockFile string // Fwactl unix socket path (for fwactl cli commands)
	PolicyPath  string // Policy file path
}

type GraphEngine struct {
	SocketFile string // Graph engine unix socket path
	BinaryPath string // Graph engine binary path
	BinaryArgs string // Graph engine binary arguments
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
	c.Controller.collectorPort = c.file.GetInt("control_plane.collector_port")
	c.Controller.deployPort = c.file.GetInt("control_plane.deploy_port")
	c.Controller.swarmPort = c.file.GetInt("control_plane.swarm_port")
	c.Controller.Collector = c.Controller.Url + ":" + fmt.Sprint(c.Controller.collectorPort)
	c.Controller.Deploy = c.Controller.Url + ":" + fmt.Sprint(c.Controller.deployPort)
	c.Controller.Swarm = c.Controller.Url + ":" + fmt.Sprint(c.Controller.swarmPort)

	// Agent
	c.Agent.AgentId = c.file.GetString("control_plane.agent_id")
	c.Agent.TenantId = c.file.GetString("control_plane.tenant_id")
	c.Agent.VerificationDuration = c.file.GetInt("control_plane.verification_duration")
	c.Agent.SnapshotCount = c.file.GetInt("control_plane.snapshot_count")
	c.Agent.SnapshotInterval = c.file.GetInt("control_plane.snapshot_interval")
	c.Agent.KeepAliveInterval = c.file.GetInt("control_plane.keepalive_interval")
	c.Agent.VerificationQueuePath = c.file.GetString("control_plane.verification_queue_path")
	c.Agent.FsmStatePath = c.file.GetString("control_plane.fsm_state_path")
	c.Agent.LoggerConfigPath = c.file.GetString("control_plane.logger_config_path")
	c.Agent.LoggerServicePath = c.file.GetString("control_plane.logger_service_path")
	c.Agent.DataplaneType = c.file.GetString("control_plane.dataplane_mode")

	// Dispatcher
	c.Dispatcher.ServicePath = c.file.GetString("dispatcher.service_path")
	c.Dispatcher.SockFile = c.file.GetString("control_plane.pd_sock_file")
	c.Dispatcher.StateFile = c.file.GetString("control_plane.dp_state_file")
	c.Dispatcher.CliSockFile = c.file.GetString("dispatcher.cli_sockfile")

	// Dataplanes
	c.Dataplanes["0"] = Dataplane{
		Mode:        c.file.GetString("dataplane0.dataplane_mode"),
		ServicePath: c.file.GetString("dataplane0.service_path"),
		VppSockFile: c.file.GetString("dataplane0.api_sockfile"),
		CpaSockFile: c.file.GetString("dataplane0.cpa_sockfile"),
		CliSockFile: c.file.GetString("dataplane0.cli_sockfile"),
		PolicyPath:  c.file.GetString("dataplane0.policy_path"),
	}
	c.Dataplanes["1"] = Dataplane{
		Mode:        c.file.GetString("dataplane1.dataplane_mode"),
		ServicePath: c.file.GetString("dataplane1.service_path"),
		VppSockFile: c.file.GetString("dataplane1.api_sockfile"),
		CpaSockFile: c.file.GetString("dataplane1.cpa_sockfile"),
		CliSockFile: c.file.GetString("dataplane1.cli_sockfile"),
		PolicyPath:  c.file.GetString("dataplane1.policy_path"),
	}

	// Tesseract
	c.GraphEngine.SocketFile = c.file.GetString("control_plane.graph_socket")
	c.GraphEngine.BinaryPath = c.file.GetString("control_plane.graph_binary")
	c.GraphEngine.BinaryArgs = c.file.GetString("control_plane.graph_args")

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
	c.file.Set("control_plane.dispatcher_service", c.Env.DispatcherService)
	c.file.Set("control_plane.dispatcher_dir", c.Env.DispatcherDir)
	c.file.Set("control_plane.dispatcher_binary", c.Env.DispatcherBinary)
	c.file.Set("control_plane.dataplane_service", c.Env.DataplaneService)
	c.file.Set("control_plane.dataplane_dir", c.Env.DataplaneDir)
	c.file.Set("control_plane.dataplane_binary", c.Env.DataplaneBinary)
	c.file.Set("control_plane.configure_script", c.Env.ConfigureScript)
	c.file.Set("control_plane.temp_dir", c.Env.TempDir)

	// Controller
	c.file.Set("control_plane.debug", c.Controller.Debug)
	c.file.Set("control_plane.controller_url", c.Controller.Url)
	c.file.Set("control_plane.collector_port", c.Controller.collectorPort)
	c.file.Set("control_plane.deploy_port", c.Controller.deployPort)
	c.file.Set("control_plane.swarm_port", c.Controller.swarmPort)

	// Agent
	c.file.Set("control_plane.keepalive_interval", c.Agent.KeepAliveInterval)
	c.file.Set("control_plane.snapshot_interval", c.Agent.SnapshotInterval)
	c.file.Set("control_plane.snapshot_count", c.Agent.SnapshotCount)
	c.file.Set("control_plane.verification_duration", c.Agent.VerificationDuration)

	// Dispatcher
	c.file.Set("control_plane.pd_sock_file", c.Dispatcher.SockFile)
	c.file.Set("control_plane.dp_state_file", c.Dispatcher.StateFile)
	c.file.Set("dispatcher.cli_sockfile", c.Dispatcher.CliSockFile)

	// Dataplanes
	c.file.Set("dataplane0.dataplane_mode", c.Dataplanes["0"].Mode)
	c.file.Set("dataplane0.api_sockfile", c.Dataplanes["0"].VppSockFile)
	c.file.Set("dataplane0.cli_sockfile", c.Dataplanes["0"].CliSockFile)
	c.file.Set("dataplane1.dataplane_mode", c.Dataplanes["1"].Mode)
	c.file.Set("dataplane1.api_sockfile", c.Dataplanes["1"].VppSockFile)
	c.file.Set("dataplane1.cli_sockfile", c.Dataplanes["1"].CliSockFile)

	// Graph Engine
	c.file.Set("control_plane.graph_socket", c.GraphEngine.SocketFile)
	c.file.Set("control_plane.graph_binary", c.GraphEngine.BinaryPath)
	c.file.Set("control_plane.graph_args", c.GraphEngine.BinaryArgs)

	return nil
}

func (c *Config) setDefaults() {
	c.file.SetDefault("control_plane.debug", false)
	c.file.SetDefault("control_plane.collector_port", 8881)
	c.file.SetDefault("control_plane.deploy_port", 8882)
	c.file.SetDefault("control_plane.swarm_port", 8880)
	c.file.SetDefault("control_plane.keepalive_interval", 30)
	c.file.SetDefault("control_plane.snapshot_interval", 60)
	c.file.SetDefault("control_plane.snapshot_count", 1)
	c.file.SetDefault("control_plane.verification_duration", 60)
	c.file.SetDefault("control_plane.verification_queue_path", "/opt/cisco/daf/etc/verification_queue.json")
	c.file.SetDefault("control_plane.fsm_state_path", "/opt/cisco/daf/etc/fsm_state.json")
	c.file.SetDefault("control_plane.token_path", "/opt/cisco/daf/etc/cpa_tokens")
	c.file.SetDefault("control_plane.logger_config_path", "/opt/cisco/daf/etc/daflogger.yaml")
	c.file.SetDefault("control_plane.logger_service_path", "/opt/cisco/daf/var/s6/services/logger")
	c.file.SetDefault("control_plane.dataplane_mode", "dual")
	c.file.SetDefault("dispatcher.service_path", "/opt/cisco/daf/var/s6/services/pd")
	c.file.SetDefault("dispatcher.dataplane_mode", "dual")
	c.file.SetDefault("dataplane0.dataplane_mode", "dual")
	c.file.SetDefault("dataplane0.service_path", "/opt/cisco/daf/var/s6/services/dp0")
	c.file.SetDefault("dataplane0.policy_path", "/opt/cisco/daf/etc/dp0-policy.json")
	c.file.SetDefault("dataplane1.dataplane_mode", "dual")
	c.file.SetDefault("dataplane1.service_path", "/opt/cisco/daf/var/s6/services/dp1")
	c.file.SetDefault("dataplane1.policy_path", "/opt/cisco/daf/etc/dp1-policy.json")
	c.file.SetDefault("control_plane.graph_socket", "/tmp/graph.sock")
	c.file.SetDefault("control_plane.graph_binary", "/opt/cisco/daf/bin/hs-ge")
	c.file.SetDefault("control_plane.graph_args", "--stand_alone=0 --load_generated_policy=0 --log_file_level=1 --start_tetragon=1 --query_docker=0 --graph_update_interval=300")
	// TODO:
}
