// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package fluentbit

// DefaultBaseConfig returns a new default config object that contains default environment
// and service configuration values
func DefaultBaseConfig() FluentBitConfig {
	return FluentBitConfig{
		Service: ServiceSection{
			HotReload: "on",
			Flush:     "${flush_interval}",
			LogLevel:  "${log_level}",
		},
		Env: map[string]string{
			"flush_interval": "1",
			"log_level":      "debug",
		},
	}
}

// DefaultDpJsonParser returns a new default dp-json parser object
func DefaultDpJsonParser() ParserSection {
	return ParserSection{
		Name:   "dp-json",
		Format: "json",
		Properties: map[string]string{
			"time_format": "%Y-%m-%dT%H:%M:%S.%LZ",
			"time_key":    "timebuf",
		},
	}
}

// DefaultFwaJsonParser returns a new default fwa-json parser object
func DefaultFwaJsonParser() ParserSection {
	return ParserSection{
		Name:   "fwa-json",
		Format: "json",
		Properties: map[string]string{
			"time_format": "%Y-%m-%dT%H:%M:%S.%LZ",
			"time_key":    "timebuf",
		},
	}
}

// DefaultFwaSyslogInput returns a new default syslog input object for FWA
func DefaultFwaSyslogInput() InputSection {
	return InputSection{
		Name: "syslog",
		Tag:  "fwa-input",
		Properties: map[string]string{
			"mode":      "unix_udp",
			"unix_perm": "0644",
			"parser":    "fwa-json",
			"path":      "/tmp/fluentbit_fwa.sock",
			"threaded":  "true",
		},
		Processors: ProcessorSection{
			Logs: []ProcessorLogsSection{
				{
					Name: "lua",
					Properties: map[string]string{
						"call": "cb_syslog",
						"code": `function cb_syslog(tag, timestamp, record)
	local formatted_message = ""

	if record["msg_code"] == 1 then  -- SYSLOG_POLICY_CHANGE
		formatted_message = "[FWPOLICY]"
			.. " op=" .. (record["policy_operation"] or "")
			.. " id=" .. (record["policy_id"] or "")
	elseif record["msg_code"] == 2 then  -- SYSLOG_CONFIG_CHANGE
		formatted_message = "[FWCONFIG]"
			.. " op=" .. (record["config_operation"] or "")
			.. " type=" .. (record["config_type"] or "")
	else
		formatted_message = "[GENERIC] event_code=" .. (record["msg_code"] or "unknown")
			.. " facility=" .. (record["facility"] or "")
			.. " severity=" .. (record["severity"] or "")
			.. " priority=" .. (record["priority"] or "")
			.. " hostname=" .. (record["hostname"] or "")
			.. " pid=" .. (record["pid"] or "")
	end

	record["message"] = formatted_message
	return 1, timestamp, record
end`,
					},
				},
			},
		},
	}
}

// DefaultDpSyslogInput returns a new default syslog input object for DP
func DefaultDpSyslogInput() InputSection {
	return InputSection{
		Name: "syslog",
		Tag:  "dp-input",
		Properties: map[string]string{
			"mode":      "unix_udp",
			"unix_perm": "0644",
			"parser":    "dp-json",
			"path":      "/tmp/fluentbit_dp.sock",
			"threaded":  "true",
		},
		Processors: ProcessorSection{
			Logs: []ProcessorLogsSection{
				{
					Name: "lua",
					Properties: map[string]string{
						"call": "cb_syslog",
						"code": `function cb_syslog(tag, timestamp, record)
	local formatted_message = ""

	if record["msg_code"] == 1 then  -- SYSLOG_POLICY_MATCH
		formatted_message = "[FWPOLICY] policy_match"
			.. " src_ip=" .. (record["src_ip"] or "")
			.. " dst_ip=" .. (record["dst_ip"] or "")
			.. " dst_port=" .. (record["dst_port"] or "")
			.. " protocol=" .. (record["protocol"] or "")
			.. " decision=" .. (record["policy_decision"] or "")
			.. " severity=" .. (record["severity"] or "")
			.. " count=" .. (record["count"] or "")
	elseif record["msg_code"] == 2 then  -- SYSLOG_FLOW_DELETE
		local reason = record["del_reason"] or "unknown"
		formatted_message = "[FWDELETE] reason= " .. reason
			.. " src_ip=" .. (record["src_ip"] or "")
			.. " dst_ip=" .. (record["dst_ip"] or "")
			.. " dst_port=" .. (record["dst_port"] or "")
			.. " protocol=" .. (record["protocol"] or "")
			.. " severity=" .. (record["severity"] or "")
			.. " count=" .. (record["count"] or "")
	elseif record["msg_code"] == 3 or record["msg_code"] == 4 then  -- LOG_ERROR_FLOW or LOG_ERROR_SESSION
        formatted_message = "[FWFLOWERROR] error= " .. (record["error_str"] or "")
            .. " src_ip=" .. (record["src_ip"] or "")
            .. " dst_ip=" .. (record["dst_ip"] or "")
            .. " dst_port=" .. (record["dst_port"] or "")
            .. " protocol=" .. (record["protocol"] or "")
            .. " severity=" .. (record["severity"] or "")
            .. " count=" .. (record["count"] or "")
            .. " evt_code=" .. (record["evt_code"] or "")			
	else
		formatted_message = "[GENERIC] event_code=" .. (record["msg_code"] or "unknown")
			.. " src_ip=" .. (record["src_ip"] or "")
			.. " dst_ip=" .. (record["dst_ip"] or "")
			.. " dst_port=" .. (record["dst_port"] or "")
			.. " protocol=" .. (record["protocol"] or "")
			.. " facility=" .. (record["facility"] or "")
			.. " severity=" .. (record["severity"] or "")
			.. " priority=" .. (record["priority"] or "")
			.. " hostname=" .. (record["hostname"] or "")
			.. " pid=" .. (record["pid"] or "")
			.. " count=" .. (record["count"] or "")

		if record["policy_decision"] then
			formatted_message = formatted_message .. " decision=" .. record["policy_decision"]
		end
		if record["policy_name"] then
			formatted_message = formatted_message .. " policy_name=" .. record["policy_name"]
		end
		if record["del_reason"] then
			formatted_message = formatted_message .. " del_reason=" .. record["del_reason"]
		end
	end

	record["message"] = formatted_message
	return 1, timestamp, record
end`,
					},
				},
			},
		},
	}
}

// DefaultStdoutOutput returns a new default stdout output object
func DefaultStdoutOutput() OutputSection {
	return OutputSection{
		Name:  "stdout",
		Match: "*",
		Properties: map[string]string{
			"format": "json",
		},
	}
}

// DefaultDpSyslogOutput returns a new default syslog output object for DP
func DefaultDpSyslogOutput() OutputSection {
	return OutputSection{
		Name:  "syslog",
		Match: "",
		Properties: map[string]string{
			"host":                "127.0.0.1",
			"port":                "514",
			"mode":                "tcp",
			"syslog_format":       "rfc5424",
			"syslog_severity_key": "severity_code",
			"syslog_facility_key": "facility",
			"syslog_hostname_key": "hostname",
			"syslog_appname_key":  "appname",
			"syslog_procid_key":   "pid",
			"syslog_msgid_key":    "msg_code",
			"syslog_sd_key":       "extradata",
			"syslog_message_key":  "message",
		},
	}
}

// DefaultDpTimescapeOutput returns a new default timescape output object for DP
func DefaultDpTimescapeOutput() OutputSection {
	return OutputSection{
		Name:  "http",
		Match: "",
		Properties: map[string]string{
			"host":   "127.0.0.1",
			"port":   "4260",
			"uri":    "/push",
			"format": "json",
		},
	}
}
