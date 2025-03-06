//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mandate

import (
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	require.NoError(t, err)
	tsm := NewTestSensorManager()
	cnf := ManagerConf{
		URL:           filepath.Join(tmpDir, "mandate.yaml"),
		RefreshPeriod: 1 * time.Second,
	}

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()

		synctest.Wait()
		status := mgr.Status()
		// the first refresh will fail (no mandate file)
		require.Equal(t, 1, status.Log.Total)
		require.Equal(t, 1, status.Log.Failures)

		synctest.Wait()
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		// the second refresh will fail as well (same reason)
		require.Equal(t, 2, status.Log.Total)
		require.Equal(t, 2, status.Log.Failures)

		// NB: let time pass so that the refresh timeout is triggered
		time.Sleep(time.Second * 2)
		status = mgr.Status()
		require.Greater(t, status.Log.Total, 2)
		require.Greater(t, status.Log.Failures, 2)

		// copy the test data (including the mandate file)
		// and check that now everything succeeds
		err = os.CopyFS(tmpDir, os.DirFS("testdata"))
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.Equal(t, 1, status.Log.Total-status.Log.Failures)

		// change the mandate file to be a version that includes a broken policy
		oldFailures := status.Log.Failures
		oldTotal := status.Log.Total
		err = os.Rename(
			filepath.Join(tmpDir, "mandate-failure.yaml"),
			filepath.Join(tmpDir, "mandate.yaml"),
		)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.NotNil(t, status.Mandate)
		require.Equal(t, "1.0.0", status.Mandate.Version)
		require.Equal(t, status.Log.Total, oldTotal+1)
		require.Equal(t, status.Log.Failures, oldFailures+1)

		// change the mandate file to a new file that works
		oldFailures = status.Log.Failures
		oldTotal = status.Log.Total
		err = os.Rename(
			filepath.Join(tmpDir, "mandate-2.0.yaml"),
			filepath.Join(tmpDir, "mandate.yaml"),
		)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.NotNil(t, status.Mandate)
		require.Equal(t, "2.0.0", status.Mandate.Version)
		require.Equal(t, status.Log.Total, oldTotal+1)
		require.Equal(t, status.Log.Failures, oldFailures)
	})
}
