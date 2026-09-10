// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alerts

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	splunkHec "github.com/isovalent/hubble-fgs/pkg/splunk/hec"
)

var getPerms = sync.OnceValue(func() os.FileMode {
	perms, err := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
	if err != nil {
		logger.GetLogger().Info("alerts: failed to parse config export file permission, falling back to default",
			logfields.Error, err,
			"config-export-file-perm", option.Config.ExportFilePerm,
			"default", perms)
	}
	return perms
})

type logWriter struct {
	l                *lumberjack.Logger
	hec              io.Writer
	rotateTimer      *time.Timer
	rotationInterval time.Duration
	closed           bool
	// NB: the lock is used to protect from a race if Close() and rotate() execute concurrently.
	mu sync.Mutex
}

func (lw *logWriter) Write(p []byte) (int, error) {
	n, err := lw.l.Write(p)
	if lw.hec != nil && n > 0 {
		// Shipping to Splunk is best effort and must not fail the file write.
		lw.hec.Write(p[:n])
	}
	return n, err
}

func (lw *logWriter) Close() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	err := lw.l.Close()
	if lw.rotateTimer != nil {
		lw.rotateTimer.Stop()
	}
	lw.closed = true
	lw.rotateTimer = nil
	return err
}

func (lw *logWriter) rotate() {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if !lw.closed {
		lw.l.Rotate()
		lw.rotateTimer = time.AfterFunc(
			lw.rotationInterval,
			lw.rotate,
		)
	}
}

func newLogWriter(filename string, maxSize int, maxBackups int, compress bool, rotationInterval time.Duration) (io.WriteCloser, error) {
	// use the same configuration options as the export file
	lw := &logWriter{
		// NB: lumberjack locks before every Write, which is something our code depends on
		// to not get mangled entries for the cases where multiple writers exist.
		l: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    maxSize,
			MaxBackups: maxBackups,
			Compress:   compress,
			FileMode:   getPerms(),
		},
		hec: splunkHec.Writer(enterpriseOption.SplunkHECSourcetypeAlerts, filename),
	}

	// configure periodic rotation
	if rotationInterval > 0 {
		lw.rotationInterval = rotationInterval
		lw.rotateTimer = time.AfterFunc(
			rotationInterval,
			lw.rotate,
		)
	}

	return lw, nil
}
