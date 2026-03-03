// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build windows

package powershell

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
)

type System struct {
	Provider struct {
		Name string `xml:"Name,attr"`
		Guid string `xml:"Guid,attr"`
	} `xml:"Provider"`
	EventID     int    `xml:"EventID"`
	Version     int    `xml:"Version"`
	Level       int    `xml:"Level"`
	Task        int    `xml:"Task"`
	Opcode      int    `xml:"Opcode"`
	Keywords    string `xml:"Keywords"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	EventRecordID int `xml:"EventRecordID"`
	Correlation   struct {
		ActivityID string `xml:"ActivityID,attr"`
	} `xml:"Correlation"`
	Execution struct {
		ProcessID int `xml:"ProcessID,attr"`
		ThreadID  int `xml:"ThreadID,attr"`
	} `xml:"Execution"`
	Channel  string `xml:"Channel"`
	Computer string `xml:"Computer"`
	Security struct {
		UserID string `xml:"UserID,attr"`
	} `xml:"Security"`
}

type EventData struct {
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"Data"`
}

type Event struct {
	XMLName   xml.Name  `xml:"Event"`
	System    System    `xml:"System"`
	EventData EventData `xml:"EventData"`
}

type WindowsEvent struct {
	EventID int
	Pid     uint64
	Tid     uint64
	Uid     uint32
}

type PowerShellEvent struct {
	Common          processapi.MsgCommon
	WinEvent        WindowsEvent
	ScriptBlockText string
	CommandLine     string
	ScriptPath      string
	PowerShellPath  string
	EngineVersion   string
	CommandName     string
	Payload         string
}

type PowerShellCmdEvent struct {
	Common          processapi.MsgCommon
	WinEvent        WindowsEvent
	ScriptBlockText string
}

func parseEvent(xmlData string) (*Event, error) {
	var event Event
	if err := xml.Unmarshal([]byte(xmlData), &event); err != nil {
		return nil, fmt.Errorf("error parsing XML: %w", err)
	}
	return &event, nil
}

// parseContextInfo extracts key=value pairs from the ContextInfo Data field.
// The field uses a mix of newlines and inline spacing, e.g.:
//
//	Host Name = ConsoleHost Host Version = 5.1.26100.7462
//	Host Application = C:\...\PowerShell.exe Engine Version = 5.1.26100.7462
func parseContextInfo(raw string) map[string]string {
	result := make(map[string]string)

	// Known keys in order — used to split the flat string into segments.
	knownKeys := []string{
		"Engine Version",
		"Command Name",
		"Command Type",
		"Script Name",
		"Command Path",
	}

	// Build a regex that matches any known key followed by " = "
	escapedKeys := make([]string, len(knownKeys))
	for i, k := range knownKeys {
		escapedKeys[i] = regexp.QuoteMeta(k)
	}
	splitPattern := regexp.MustCompile(`(` + strings.Join(escapedKeys, "|") + `)\s*=\s*`)

	// Find all key positions
	matches := splitPattern.FindAllStringIndex(raw, -1)
	if matches == nil {
		return result
	}

	commentRe := regexp.MustCompile(`<!--.*?-->`)
	for i, match := range matches {
		keyMatch := splitPattern.FindStringSubmatch(raw[match[0]:match[1]])
		if keyMatch == nil {
			continue
		}
		key := strings.TrimSpace(keyMatch[1])

		// Value runs from end of this match to start of next match (or end of string)
		valueStart := match[1]
		valueEnd := len(raw)
		if i+1 < len(matches) {
			valueEnd = matches[i+1][0]
		}

		value := strings.TrimSpace(raw[valueStart:valueEnd])
		value = strings.TrimSpace(commentRe.ReplaceAllString(value, ""))
		result[key] = value
	}

	return result
}

// timeToKernelNs converts an ISO-8601 timestamp to nanoseconds since Unix epoch,
// approximating a kernel monotonic timestamp.
func timeToKernelNs(systemTime string) uint64 {
	t, err := time.Parse(time.RFC3339Nano, systemTime)
	if err != nil {
		return 0
	}
	return uint64(t.UnixNano())
}

// uidFromSID extracts the trailing RID from a Windows SID string (e.g. S-1-5-21-...-1001 → 1001).
func uidFromSID(sid string) uint32 {
	parts := strings.Split(sid, "-")
	if len(parts) == 0 {
		return 0
	}
	rid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return 0
	}
	return uint32(rid)
}

func toPowerShellEvent(e *Event) (*PowerShellEvent, error) {
	// Index EventData by Name for easy lookup
	dataMap := make(map[string]string)
	for _, d := range e.EventData.Data {
		dataMap[d.Name] = strings.TrimSpace(d.Value)
	}

	ctx := parseContextInfo(dataMap["ContextInfo"])

	psEvent := &PowerShellEvent{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_POWERSHELL,
			Ktime: timeToKernelNs(e.System.TimeCreated.SystemTime)},
		WinEvent: WindowsEvent{
			EventID: e.System.EventID,
			Pid:     uint64(e.System.Execution.ProcessID),
			Tid:     uint64(e.System.Execution.ThreadID),
			Uid:     uidFromSID(e.System.Security.UserID),
		},
		ScriptBlockText: dataMap["ScriptBlockText"],
		Payload:         dataMap["Payload"],
		PowerShellPath:  ctx["Host Application"],
		EngineVersion:   ctx["Engine Version"],
		CommandName:     ctx["Command Name"],
		ScriptPath:      ctx["Script Name"],
	}

	return psEvent, nil
}

func toPowerShellCmdEvent(e *Event) (*PowerShellCmdEvent, error) {
	// Index EventData by Name for easy lookup
	dataMap := make(map[string]string)
	for _, d := range e.EventData.Data {
		dataMap[d.Name] = strings.TrimSpace(d.Value)
	}

	psEvent := &PowerShellCmdEvent{
		Common: processapi.MsgCommon{
			Op:    ops.MSG_OP_POWERSHELL,
			Ktime: timeToKernelNs(e.System.TimeCreated.SystemTime)},
		WinEvent: WindowsEvent{
			EventID: e.System.EventID,
			Pid:     uint64(e.System.Execution.ProcessID),
			Tid:     uint64(e.System.Execution.ThreadID),
			Uid:     uidFromSID(e.System.Security.UserID),
		},

		ScriptBlockText: dataMap["ScriptBlockText"],
	}

	return psEvent, nil
}
