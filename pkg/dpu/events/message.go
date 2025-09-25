package events

import (
	"os"
)

const (
	// Message codes for different message types
	MSGCODE_POLICY = 1
	MSGCODE_CONFIG = 2
)

// EventLogMessage represents a structured syslog message
type EventLogMessage struct {
	// Required fields for RFC5424
	Appname      string `json:"appname"`
	Facility     int    `json:"facility"`
	Hostname     string `json:"hostname"`
	MsgCode      int    `json:"msg_code"`
	PID          int    `json:"pid"`
	Priority     int    `json:"priority"`
	Severity     string `json:"severity"`
	SeverityCode int    `json:"severity_code"`

	// Timestamp, reserved for event logger
	Timebuf string `json:"timebuf"`

	// Additional fields that are formatted into RFC5424 message field
	// Config
	OldConfigHash string `json:"old_config_hash"`
	NewConfigHash string `json:"new_config_hash"`
	// Policy
	OldPolicyHash string `json:"old_policy_hash"`
	NewPolicyHash string `json:"new_policy_hash"`
}

func NewEventLogMessage(typ int, id string) EventLogMessage {
	return EventLogMessage{
		MsgCode:      typ,
		Appname:      "hs-fwa",
		Hostname:     id,
		PID:          os.Getpid(),
		Facility:     1,
		Priority:     14,
		Severity:     "info",
		SeverityCode: 6,
	}
}
