// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package logexport

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/isovalent/ipa/l3l4networkpolicy/v1alpha"

	"github.com/isovalent/hubble-fgs/pkg/config/library"
	"github.com/isovalent/hubble-fgs/pkg/logexport"
	"github.com/isovalent/hubble-fgs/pkg/logexport/unixjson"
)

const (
	facilityUser      = 1
	appName           = "agw"
	hostnameSuffix    = ".smartswitch.isovalent.com"
	unknownIdentity   = "smartswitch-unknown"
	unknownHost       = "localhost"
	hostnameLabelMaxL = 63
)

// record is the structured log payload AGW writes to Fluent Bit.
// Field names intentionally match current Fluent Bit output key mappings.
type record struct {
	Appname      string `json:"appname"`
	Facility     int    `json:"facility"`
	Hostname     string `json:"hostname"`
	MsgCode      int    `json:"msg_code"`
	PID          int    `json:"pid"`
	Priority     int    `json:"priority"`
	Severity     string `json:"severity"`
	SeverityCode int    `json:"severity_code"`
	Timebuf      string `json:"timebuf"`
	Message      string `json:"message"`
}

// Handler mirrors slog records as structured JSON over unixgram for
// AGW-local Fluent Bit ingestion.
type Handler struct {
	socketPath string
	appName    string
	client     *unixjson.Client

	attrs []slog.Attr
	group string
}

// NewHandler creates a new log export handler that writes structured JSON
// records to the given unix socket path.
func NewHandler(socketPath string) *Handler {
	return &Handler{
		socketPath: socketPath,
		appName:    appName,
		client:     unixjson.NewClient(socketPath),
	}
}

func (h *Handler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	if h.socketPath == "" {
		return nil
	}
	if !hasExportTag(h.attrs, r) {
		return nil
	}

	severityCode := slogToSeverity(r.Level)
	rec := record{
		Appname:      h.appName,
		Facility:     facilityUser,
		Hostname:     buildHostname(),
		MsgCode:      0,
		PID:          os.Getpid(),
		Priority:     facilityUser*8 + severityCode,
		Severity:     severityName(severityCode),
		SeverityCode: severityCode,
		Message:      h.formatMessage(r),
	}

	return h.client.Write(rec)
}

// hasExportTag checks whether the record or the handler's accumulated attrs
// contain the logexport.Export sentinel attribute.
func hasExportTag(handlerAttrs []slog.Attr, r slog.Record) bool {
	for _, a := range handlerAttrs {
		if a.Key == logexport.ExportKey && a.Value.Bool() {
			return true
		}
	}
	found := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == logexport.ExportKey {
			found = a.Value.Bool()
			return false
		}
		return true
	})
	return found
}

func (h *Handler) formatMessage(r slog.Record) string {
	var b strings.Builder
	b.WriteString(r.Message)

	for _, a := range h.attrs {
		if a.Key == logexport.ExportKey {
			continue
		}
		b.WriteByte(' ')
		b.WriteString(h.formatAttrKey(a.Key))
		b.WriteByte('=')
		b.WriteString(a.Value.String())
	}

	r.Attrs(func(a slog.Attr) bool {
		if a.Key == logexport.ExportKey {
			return true
		}
		b.WriteByte(' ')
		b.WriteString(h.formatAttrKey(a.Key))
		b.WriteByte('=')
		b.WriteString(a.Value.String())
		return true
	})

	return b.String()
}

func (h *Handler) formatAttrKey(key string) string {
	if h.group == "" {
		return key
	}
	return h.group + "." + key
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &Handler{
		socketPath: h.socketPath,
		appName:    h.appName,
		client:     h.client,
		attrs:      newAttrs,
		group:      h.group,
	}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	group := h.group
	if name != "" {
		if group == "" {
			group = name
		} else {
			group = group + "." + name
		}
	}
	return &Handler{
		socketPath: h.socketPath,
		appName:    h.appName,
		client:     h.client,
		attrs:      h.attrs,
		group:      group,
	}
}

func buildHostname() string {
	label := sanitizeHostnameLabel(resolveSwitchIdentity(), unknownIdentity)
	return label + hostnameSuffix
}

func resolveSwitchIdentity() string {
	if cfgObj, ok := library.GetRepository().GetConfigObject(v1alpha.ConfigType_CONFIG_TYPE_DPU); ok && cfgObj != nil {
		if cfg := cfgObj.GetConfigDpu(); cfg != nil {
			if serial := strings.TrimSpace(cfg.GetSerialNumber()); serial != "" {
				return serial
			}
			if switchName := strings.TrimSpace(cfg.GetSwitchName()); switchName != "" {
				return switchName
			}
		}
	}

	if switchName := strings.TrimSpace(os.Getenv("CAF_SYSTEM_NAME")); switchName != "" {
		return switchName
	}
	return getFallbackHostname()
}

func getFallbackHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return unknownHost
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return unknownHost
	}
	return hostname
}

// sanitizeHostnameLabel restricts the input to DNS label-safe characters.
func sanitizeHostnameLabel(in, fallback string) string {
	in = strings.TrimSpace(in)
	if in == "" {
		return fallback
	}

	var b strings.Builder
	for _, r := range in {
		isLower := r >= 'a' && r <= 'z'
		isUpper := r >= 'A' && r <= 'Z'
		isDigit := r >= '0' && r <= '9'
		if isLower || isUpper || isDigit || r == '-' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}

	out := strings.Trim(b.String(), "-")
	if len(out) > hostnameLabelMaxL {
		out = strings.Trim(out[:hostnameLabelMaxL], "-")
	}
	if out == "" {
		return fallback
	}
	return out
}

func slogToSeverity(level slog.Level) int {
	switch {
	case level >= slog.LevelError:
		return 3 // error
	case level >= slog.LevelWarn:
		return 4 // warning
	case level >= slog.LevelInfo:
		return 6 // informational
	default:
		return 7 // debug
	}
}

func severityName(code int) string {
	switch code {
	case 0:
		return "emerg"
	case 1:
		return "alert"
	case 2:
		return "crit"
	case 3:
		return "error"
	case 4:
		return "warning"
	case 5:
		return "notice"
	case 6:
		return "info"
	default:
		return "debug"
	}
}

// MultiHandler fans out log records to a primary handler and zero or more
// mirror handlers. The primary handler's Enabled method gates all logging;
// individual mirrors decide which records to accept (e.g. Handler only
// forwards records tagged with logexport.Export).
type MultiHandler struct {
	Primary slog.Handler
	Mirrors []slog.Handler
}

func (m MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return m.Primary.Enabled(ctx, level)
}

func (m MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = m.Primary.Handle(ctx, r)
	for _, h := range m.Mirrors {
		_ = h.Handle(ctx, r)
	}
	return nil
}

func (m MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	mirrors := make([]slog.Handler, len(m.Mirrors))
	for i, h := range m.Mirrors {
		mirrors[i] = h.WithAttrs(attrs)
	}
	return MultiHandler{
		Primary: m.Primary.WithAttrs(attrs),
		Mirrors: mirrors,
	}
}

func (m MultiHandler) WithGroup(name string) slog.Handler {
	mirrors := make([]slog.Handler, len(m.Mirrors))
	for i, h := range m.Mirrors {
		mirrors[i] = h.WithGroup(name)
	}
	return MultiHandler{
		Primary: m.Primary.WithGroup(name),
		Mirrors: mirrors,
	}
}
