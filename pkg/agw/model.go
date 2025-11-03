package agw

// ------------- Log Configuration -------------

const (
	LogTypeSyslog    = "syslog"
	LogTypeIpfix     = "ipfix"
	LogTypeTimescape = "timescape"
	LogTypeSplunk    = "splunk"
)

type LogList map[string]LogConfigData

type LogConfigData struct {
	Id          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Type        string               `json:"type"`
	Config      LogConfigDataConfig  `json:"config"`
	Secrets     LogConfigDataSecrets `json:"secrets"`
}

type LogConfigDataConfig struct {
	Host string `json:"host"`
	Port string `json:"port"`
	Mode string `json:"mode"` // "tcp" or "udp"
	Tls  bool   `json:"tls"`
}

type LogConfigDataSecrets struct {
	Token       string `json:"token"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	CA          string `json:"ca"`
	Cert        string `json:"cert"`
	Key         string `json:"key"`
	KeyPassword string `json:"keyPassword"` // Not necessary??
}

type DpuConfigData struct {
	ServiceIP  string `json:"service_ip"`
	ServiceMAC string `json:"service_mac"`
	PortLow    uint32 `json:"port_low"`
	PortHigh   uint32 `json:"port_high"`
}
