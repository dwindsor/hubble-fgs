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

	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/testutils"
	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
	"github.com/stretchr/testify/require"
)

func TestManager(t *testing.T) {

	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	require.NoError(t, err)
	tsm := NewTestSensorManager()
	cnf := mandateconf.ManagerConf{
		URL:           filepath.Join(tmpDir, "mandate.yaml"),
		RefreshPeriod: 1 * time.Second,
	}

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm, nil)
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

// tests the "conf:" sections in mandate files
func TestManagerConf(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		// os.RemoveAll(tmpDir)
	})
	require.NoError(t, err)
	err = os.CopyFS(tmpDir, os.DirFS("testdata"))
	require.NoError(t, err)
	tmpPath := func(s string) string {
		return filepath.Join(tmpDir, s)
	}

	tsm := NewTestSensorManager()
	myMandate := tmpPath("mymandate.yaml")
	require.NoError(t, err)
	cnf := mandateconf.ManagerConf{
		URL:           myMandate,
		RefreshPeriod: 1 * time.Second,
	}

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm, nil)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()

		// mandate-noconf has no mode configuration, policies should maintain their mode
		err = testutils.CopyFile(myMandate, tmpPath("mandate-noconf.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "monitor"))

		// mandate conf has a global monitor configuration, so policy-1 should be also in
		// monitor mode
		err = testutils.CopyFile(myMandate, tmpPath("mandate-conf.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "monitor"))
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-1"))

		// mandate conf has a global enforce configuration and policy-1 has a monitor
		// configuration.
		err = testutils.CopyFile(myMandate, tmpPath("mandate-policy-conf.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.EnforceMode, tsm.policyMode(t, "monitor"))
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-1"))

	})
}

// tests the configure command
func TestManagerConfigure(t *testing.T) {
	var m1 = "pizza.yaml"
	var m2 = "burger.yaml"
	var t1 = 1 * time.Second
	var t2 = 7 * time.Second

	tsm := NewTestSensorManager()
	cnf := mandateconf.ManagerConf{
		URL:           m1,
		RefreshPeriod: t1,
	}

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm, nil)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.Stop()

		status := mgr.Status()
		require.Equal(t, m1, status.Conf.URL)
		require.Equal(t, t1, status.Conf.RefreshPeriod)

		err = mgr.Configure(ConfArg{
			URL: &m2,
		})
		require.NoError(t, err)
		synctest.Wait()
		status = mgr.Status()
		require.Equal(t, m2, status.Conf.URL)
		require.Equal(t, t1, status.Conf.RefreshPeriod)

		err = mgr.Configure(ConfArg{
			RefreshPeriod: &t2,
		})
		require.NoError(t, err)
		synctest.Wait()
		status = mgr.Status()
		require.Equal(t, m2, status.Conf.URL)
		require.Equal(t, t2, status.Conf.RefreshPeriod)
		require.Equal(t, 1, status.Log.Total)

		err = mgr.Configure(ConfArg{
			URL:           &m1,
			RefreshPeriod: &t1,
			Refresh:       true,
		})
		require.NoError(t, err)
		synctest.Wait()
		status = mgr.Status()
		require.Equal(t, m1, status.Conf.URL)
		require.Equal(t, t1, status.Conf.RefreshPeriod)
		require.Equal(t, 2, status.Log.Total)

		err = mgr.Configure(ConfArg{
			Refresh: true,
		})
		synctest.Wait()
		require.NoError(t, err)
		status = mgr.Status()
		require.Equal(t, m1, status.Conf.URL)
		require.Equal(t, t1, status.Conf.RefreshPeriod)
		require.Equal(t, 3, status.Log.Total)
	})
}

func TestManagerNoAlerts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	require.NoError(t, err)
	tsm := NewTestSensorManager()
	cnf := mandateconf.ManagerConf{
		URL:           filepath.Join(tmpDir, "mandate-alerts.yaml"),
		RefreshPeriod: 1 * time.Second,
	}
	err = os.CopyFS(tmpDir, os.DirFS("testdata"))
	require.NoError(t, err)

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm, nil)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()
		synctest.Wait()
		// should fail, because alert manager is disabled
		status := mgr.Status()
		require.Equal(t, 1, status.Log.Total)
		require.Equal(t, 1, status.Log.Failures)
	})
}

func TestManagerAlerts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})
	require.NoError(t, err)
	tsm := NewTestSensorManager()
	tam := NewTestAlertManager()
	cnf := mandateconf.ManagerConf{
		URL:           filepath.Join(tmpDir, "mandate-alerts.yaml"),
		RefreshPeriod: 1 * time.Second,
	}
	err = os.CopyFS(tmpDir, os.DirFS("testdata"))
	require.NoError(t, err)

	synctest.Run(func() {
		mgr, err := NewManager(cnf, tsm, tam)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()
		synctest.Wait()
		status := mgr.Status()
		require.Equal(t, 1, status.Log.Total)
		require.Equal(t, 0, status.Log.Failures)
		//txt, err := json.MarshalIndent(&status, "", "  ")
		//fmt.Printf("%s\n", string(txt))
		//fmt.Printf("%v\n", status)
	})
}
