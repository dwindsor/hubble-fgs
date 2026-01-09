// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package events

import (
	"fmt"
	"os"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
)

const (
	BASE_HOSTNAME = "smartswitch.isovalent.com"
	BASE_APPNAME  = "hs-fwa-app"

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
	ConfigOperation string `json:"config_operation"`
	ConfigType      string `json:"config_type"`
	ConfigValue     string `json:"config_value"`
	// Policy
	PolicyOperation string `json:"policy_operation"`
	PolicyId        string `json:"policy_id"`
	PolicyValue     string `json:"policy_value"`
}

func NewEventLogMessage(typ int) EventLogMessage {
	appname := BASE_APPNAME
	hostname := BASE_HOSTNAME
	var dpuCfg v1alpha.DpuConfig
	err := library.GetRepository().GetConfig(v1alpha.ConfigType_CONFIG_TYPE_DPU, &dpuCfg)
	if err == nil {
		appname = fmt.Sprintf("%s.%d", BASE_APPNAME, dpuCfg.DpuId)
		hostname = fmt.Sprintf("%s.%s", dpuCfg.SerialNumber, BASE_HOSTNAME)
	}

	return EventLogMessage{
		MsgCode:      typ,
		Appname:      appname,
		Hostname:     hostname,
		PID:          os.Getpid(),
		Facility:     1,
		Priority:     14,
		Severity:     "info",
		SeverityCode: 6,
	}
}
