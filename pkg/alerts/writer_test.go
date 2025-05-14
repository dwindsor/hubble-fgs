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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/require"
)

// NB: the code is not easy to test because it uses timers (for the rotation interval) and its
// effects are only visible in the filesystem.
func TestWriter(t *testing.T) {
	// set this to true to print the list of log files
	printLogFiles := false
	// set this to true to test in actual time. Takes longer and its not suitable for CI
	realTime := false

	oldMaxSize := option.Config.ExportFileMaxSizeMB
	option.Config.ExportFileMaxSizeMB = 1
	oldMaxBackups := option.Config.ExportFileMaxBackups
	option.Config.ExportFileMaxBackups = 3

	oldRotationInterval := option.Config.ExportFileRotationInterval
	if realTime {
		option.Config.ExportFileRotationInterval = 1 * time.Second
	}
	t.Cleanup(func() {
		option.Config.ExportFileMaxSizeMB = oldMaxSize
		option.Config.ExportFileMaxBackups = oldMaxBackups
		option.Config.ExportFileRotationInterval = oldRotationInterval
	})

	dir := t.TempDir()
	fname := filepath.Join(dir, "logfile.log")

	// return the number of directory intries in dir
	nrLogFiles := func() int {
		dentries, err := os.ReadDir(dir)
		require.NoError(t, err)
		if printLogFiles {
			for _, dentry := range dentries {
				info, err := dentry.Info()
				require.NoError(t, err)
				t.Logf("dentry=%s (size:%d)\n", dentry.Name(), info.Size())
			}
		}
		return len(dentries)
	}

	totalLogFileSize := func() int64 {
		ret := int64(0)
		dentries, err := os.ReadDir(dir)
		require.NoError(t, err)
		for _, dentry := range dentries {
			info, err := dentry.Info()
			if err != nil {
				continue
			}
			size := info.Size()
			if printLogFiles {
				t.Logf("dentry=%s (size:%d)\n", dentry.Name(), size)
			}
			ret += size
		}
		return ret
	}

	// write file n times its rotation limit
	writeNRotates := func(lw *logWriter, n int) {
		data := make([]byte, 1024*1024*option.Config.ExportFileMaxSizeMB)
		for range n {
			_, err := lw.Write(data)
			// NB: if there is a partial error here, we can be smarter and write the rest of the
			// data to the buffer
			require.NoError(t, err)
			// NB: do a sync to ensure files are flushed and fs changes are visible
			syncFS()
		}
	}

	wc, err := newLogWriter(fname)
	lw := wc.(*logWriter)
	t.Cleanup(func() {
		lw.Close()
	})

	// ensure that ExportFileMaxBackups is respected
	require.NoError(t, err)
	writeNRotates(lw, 10)
	// NB: normally, and indeed in most cases, the files are going to be max_backups+1.
	// In some cases, however, the rotation's affect are not visible in the fs when we test.
	// To counter that, we add a slack of one. Note that it's still the case that the test will
	// fail if no rotation happens, since we write enough data for 10 rotations, while we check
	// for 3 + 1 + 1 = 5 files.
	expectedfilesnr := (option.Config.ExportFileMaxBackups + 1) + 1
	expectedbytes := int64(1024 * 1024 * option.Config.ExportFileMaxSizeMB * expectedfilesnr)
	// NB: using "LessOrEqual" in these tests to avoid races/flakes. In the majority of the
	// cases, we seem to be hitting equal but not always.
	require.LessOrEqual(t, nrLogFiles(), expectedfilesnr)
	nbytes := totalLogFileSize()
	require.LessOrEqual(t, nbytes, expectedbytes)
	require.Greater(t, nbytes, int64(0))

	nrotations := expectedfilesnr + 1
	if realTime {
		waitTime := time.Duration(int(option.Config.ExportFileRotationInterval) * nrotations)
		time.Sleep(waitTime)
	} else {
		for range nrotations {
			lw.rotate()
			// NB: do a sync to ensure files are flushed and fs changes are visible
			syncFS()
		}
	}

	nbytes = totalLogFileSize()
	require.Equal(t, int64(0), nbytes)
}
