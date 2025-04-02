//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"io"
	"os"
	"sync"
	"time"

	"github.com/cilium/lumberjack/v2"
	"github.com/cilium/tetragon/pkg/fileutils"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

var getPerms = sync.OnceValue(func() os.FileMode {
	perms, err := fileutils.RegularFilePerms(option.Config.ExportFilePerm)
	if err != nil {
		logger.GetLogger().
			WithError(err).
			WithField("config-export-file-perm", option.Config.ExportFilePerm).
			WithField("default", perms).
			Info("alerts: failed to parse config export file permission, falling back to default")
	}
	return perms
})

type logWriter struct {
	l           *lumberjack.Logger
	rotateTimer *time.Timer
	closed      bool
	// NB: the lock is used to protect from a race if Close() and rotate() execute concurrently.
	mu sync.Mutex
}

func (lw *logWriter) Write(p []byte) (int, error) {
	return lw.l.Write(p)
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
			option.Config.ExportFileRotationInterval,
			lw.rotate,
		)
	}
}

func newLogWriter(filename string) (io.WriteCloser, error) {

	// use the same configuration options as the export file
	lw := &logWriter{
		l: &lumberjack.Logger{
			Filename:   filename,
			MaxSize:    option.Config.ExportFileMaxSizeMB,
			MaxBackups: option.Config.ExportFileMaxBackups,
			Compress:   option.Config.ExportFileCompress,
			FileMode:   getPerms(),
		},
	}

	// configure periodic rotation
	if option.Config.ExportFileRotationInterval > 0 {
		lw.rotateTimer = time.AfterFunc(
			option.Config.ExportFileRotationInterval,
			lw.rotate,
		)
	}

	return lw, nil
}
