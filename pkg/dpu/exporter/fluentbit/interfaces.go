package fluentbit

var (
	FLB_SSH_DIR = "/opt/cisco/daf/etc/.ssh"
)

type FluentBitConfig struct {
	Service          ServiceSection           `yaml:"service,omitempty"`
	Pipeline         PipelineSection          `yaml:"pipeline,omitempty"`
	Parsers          []ParserSection          `yaml:"parsers,omitempty"`
	MultilineParsers []MultilineParserSection `yaml:"multiline_parsers,omitempty"`
	Plugins          []PluginSection          `yaml:"plugins,omitempty"`
	UpstreamServers  []UpstreamServerSection  `yaml:"upstream_servers,omitempty"`
	Env              map[string]string        `yaml:"env,omitempty"`
}

type ServiceSection struct {
	Flush       string `yaml:"flush,omitempty"`
	Daemon      string `yaml:"daemon,omitempty"`
	HotReload   string `yaml:"hot_reload,omitempty"`
	LogLevel    string `yaml:"log_level,omitempty"`
	ParsersFile string `yaml:"parsers_file,omitempty"`
	HTTPServer  string `yaml:"http_server,omitempty"`
	HTTPListen  string `yaml:"http_listen,omitempty"`
	HTTPPort    string `yaml:"http_port,omitempty"`
}

type PipelineSection struct {
	Inputs  []InputSection  `yaml:"inputs,omitempty"`
	Filters []FilterSection `yaml:"filters,omitempty"`
	Outputs []OutputSection `yaml:"outputs,omitempty"`
}

type InputSection struct {
	Name       string            `yaml:"name,omitempty"`
	Alias      string            `yaml:"alias,omitempty"`
	Tag        string            `yaml:"tag,omitempty"`
	Properties map[string]string `yaml:",inline"`
	Processors ProcessorSection  `yaml:"processors,omitempty"`
}

type FilterSection struct {
	Name       string            `yaml:"name,omitempty"`
	Match      string            `yaml:"match,omitempty"`
	Alias      string            `yaml:"alias,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type OutputSection struct {
	Name       string            `yaml:"name,omitempty"`
	Match      string            `yaml:"match,omitempty"`
	Alias      string            `yaml:"alias,omitempty"`
	Properties map[string]string `yaml:",inline"`
	Processors ProcessorSection  `yaml:"processors,omitempty"`
}

type ProcessorSection struct {
	Logs    []ProcessorLogsSection    `yaml:"logs,omitempty"`
	Metrics []ProcessorMetricsSection `yaml:"metrics,omitempty"`
}

type ProcessorLogsSection struct {
	Name       string            `yaml:"name,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type ProcessorMetricsSection struct {
	Name       string            `yaml:"name,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type ParserSection struct {
	Name       string            `yaml:"name,omitempty"`
	Format     string            `yaml:"format,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type MultilineParserSection struct {
	Name       string            `yaml:"name,omitempty"`
	Type       string            `yaml:"type,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type StreamProcessorSection struct {
	Name string `yaml:"name,omitempty"`
	Exec string `yaml:"exec,omitempty"`
}

type PluginSection struct {
	Name       string            `yaml:"name,omitempty"`
	Path       string            `yaml:"path,omitempty"`
	Properties map[string]string `yaml:",inline"`
}

type UpstreamServerSection struct {
	Name string `yaml:"name,omitempty"`
	Host string `yaml:"host,omitempty"`
	Port int    `yaml:"port,omitempty"`
}
