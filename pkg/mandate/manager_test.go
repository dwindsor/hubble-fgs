// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package mandate

import (
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/tetragon/pkg/policyconf"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/require"

	testutils2 "github.com/isovalent/hubble-fgs/pkg/testutils"

	mandateconf "github.com/isovalent/hubble-fgs/pkg/mandate/conf"
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

	handler, cleanup := testutils2.SetupLogCheckerHandler()
	t.Cleanup(cleanup)

	synctest.Test(t, func(t *testing.T) {
		mgr, err := NewManager(cnf, tsm, nil)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()

		synctest.Wait()
		status := mgr.Status()
		// the first refresh will fail (no mandate file)
		require.Equal(t, 1, status.Log.Total)
		require.Equal(t, 1, status.Log.Failures)
		require.Empty(t, mgr.loadedPolicies)

		synctest.Wait()
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		// the second refresh will fail as well (same reason)
		require.Equal(t, 2, status.Log.Total)
		require.Equal(t, 2, status.Log.Failures)
		require.Empty(t, mgr.loadedPolicies)

		// NB: let time pass so that the refresh timeout is triggered
		time.Sleep(time.Second * 2)
		status = mgr.Status()
		require.Greater(t, status.Log.Total, 2)
		require.Greater(t, status.Log.Failures, 2)
		require.Empty(t, mgr.loadedPolicies)

		// copy the test data (including the mandate file)
		// and check that now everything succeeds
		err = os.CopyFS(tmpDir, os.DirFS("testdata"))
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.Equal(t, 1, status.Log.Total-status.Log.Failures)
		require.Len(t, mgr.loadedPolicies, 2) // 1.yaml, 2.yaml

		// change the mandate file to a new file without conf
		oldFailures := status.Log.Failures
		oldTotal := status.Log.Total
		err = os.Rename(
			filepath.Join(tmpDir, "mandate-noconf.yaml"),
			filepath.Join(tmpDir, "mandate.yaml"),
		)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.NotNil(t, status.Mandate)
		require.Equal(t, "", status.Mandate.Version)
		require.Equal(t, status.Log.Total, oldTotal+1)
		require.Equal(t, status.Log.Failures, oldFailures)
		require.Len(t, mgr.loadedPolicies, 2) // 1.yaml, monitor.yaml
		// skipping 1.yaml
		require.NoError(t, handler.MatchLine("skipping already loaded policy"))

		// change the mandate file to a new file with mode config
		oldFailures = status.Log.Failures
		oldTotal = status.Log.Total
		err = os.Rename(
			filepath.Join(tmpDir, "mandate-conf.yaml"),
			filepath.Join(tmpDir, "mandate.yaml"),
		)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.NotNil(t, status.Mandate)
		require.Equal(t, "", status.Mandate.Version)
		require.Equal(t, status.Log.Total, oldTotal+1)
		require.Equal(t, status.Log.Failures, oldFailures)
		require.Len(t, mgr.loadedPolicies, 2) // 1.yaml, monitor.yaml
		require.NoError(t, handler.MatchLines([]string{
			// skipping 1.yaml
			"skipping already loaded policy",
			// skipping monitor.yaml
			"skipping already loaded policy",
			// enforcing "monitor" mode on 1.yaml
			"enforcing new mode for loaded policy",
		}))

		// change the mandate file to be a version that includes a broken policy
		oldFailures = status.Log.Failures
		oldTotal = status.Log.Total
		err = os.Rename(
			filepath.Join(tmpDir, "mandate-failure.yaml"),
			filepath.Join(tmpDir, "mandate.yaml"),
		)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		status = mgr.Status()
		require.NotNil(t, status.Mandate)
		require.Equal(t, "", status.Mandate.Version)
		require.Equal(t, status.Log.Total, oldTotal+1)
		require.Equal(t, status.Log.Failures, oldFailures+1)
		require.Len(t, mgr.loadedPolicies, 2) // 1.yaml, monitor.yaml (everything has been rolled back to working version)
		// skipping 1.yaml (mandate-failure.yaml loads 1.yaml, 2.yaml and then fails loading fail.yaml)
		require.NoError(t, handler.MatchLine("skipping already loaded policy"))

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
		require.Len(t, mgr.loadedPolicies, 3) // 1.yaml, 2.yaml, 3.yaml
		require.NoError(t, handler.MatchLines([]string{
			// skipping 1.yaml
			"skipping already loaded policy",
			// enforcing "enforce" mode on 1.yaml since neither:
			// * mandate conf.mode
			// * mandate policies[].mode
			// * policy
			// specify a mode, therefore we default at "enforce".
			"enforcing new mode for loaded policy",
		}))
	})
}

// tests the "conf:" sections in mandate files
func TestManagerConf(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
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

	synctest.Test(t, func(t *testing.T) {
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

// tests the "conf: mode:" sections in mandate files
func TestManagerMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mandate-test-*")
	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
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

	synctest.Test(t, func(t *testing.T) {
		mgr, err := NewManager(cnf, tsm, nil)
		require.NoError(t, err)
		mgr.Start()
		defer mgr.stop()

		// mandate-001 enforces monitor mode
		err = testutils.CopyFile(myMandate, tmpPath("mandate-001.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-1"))

		// mandate-002 enforces enforce mode from within policy-1.conf.mode,
		// while enforcing monitor mode from conf.mode.
		err = testutils.CopyFile(myMandate, tmpPath("mandate-002.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.EnforceMode, tsm.policyMode(t, "policy-1"))
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-2"))

		// mandate-003 enforces back monitor mode from within policy-1.conf.mode
		err = testutils.CopyFile(myMandate, tmpPath("mandate-003.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-1"))
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-2"))

		// mandate-002 enforces again enforce mode from within policy-1.conf.mode
		err = testutils.CopyFile(myMandate, tmpPath("mandate-002.yaml"), 0644)
		require.NoError(t, err)
		mgr.Refresh()
		synctest.Wait()
		require.Equal(t, policyconf.EnforceMode, tsm.policyMode(t, "policy-1"))
		require.Equal(t, policyconf.MonitorMode, tsm.policyMode(t, "policy-2"))
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

	synctest.Test(t, func(t *testing.T) {
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

	synctest.Test(t, func(t *testing.T) {
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

	synctest.Test(t, func(t *testing.T) {
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
