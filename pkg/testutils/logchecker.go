// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package testutils

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
)

type LogCheckerHandler struct {
	logger *slog.Logger
	logs   []slog.Record
}

type LogCleanupFunc func()

// Setup a LogCheckerHandler object wrapping global DefaultSlogLogger
// to allow tests to check logged output.
func SetupLogCheckerHandler() (*LogCheckerHandler, LogCleanupFunc) {
	currLogger := logger.DefaultSlogLogger
	handler := &LogCheckerHandler{logger: currLogger}
	logger.DefaultSlogLogger = slog.New(handler)
	return handler, func() {
		logger.DefaultSlogLogger = currLogger
	}
}

func (h *LogCheckerHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *LogCheckerHandler) Handle(ctx context.Context, r slog.Record) error {
	h.logs = append(h.logs, r)
	return h.logger.Handler().Handle(ctx, r)
}

func (h *LogCheckerHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

func (h *LogCheckerHandler) WithGroup(_ string) slog.Handler {
	return h
}

// MatchLine matches last logged line against user provided text
func (h *LogCheckerHandler) MatchLine(line string) error {
	return h.matchNLastLine(line, 1)
}

// MatchLines verifies that the provided lines match the logged lines in reverse order, starting from the most recent one.
func (h *LogCheckerHandler) MatchLines(lines []string) error {
	for idx, line := range lines {
		if err := h.matchNLastLine(line, len(lines)-idx); err != nil {
			return err
		}
	}
	return nil
}

func (h *LogCheckerHandler) matchNLastLine(line string, idx int) error {
	lidx := len(h.logs) - idx
	if lidx < 0 || lidx >= len(h.logs) {
		return fmt.Errorf("log line not matching; requested last line %d from %d lines", idx, len(h.logs))
	}

	message := h.logs[lidx].Message
	if strings.Contains(message, line) {
		return nil
	}
	return fmt.Errorf("log line not matching; requested %q, seen %q", line, message)
}
