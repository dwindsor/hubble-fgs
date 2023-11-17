//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/spf13/viper"
)

var (
	oldAdminFgsConfDir    = "/etc/hubble-fgs/"
	oldAdminFgsConfDropIn = "/etc/hubble-fgs/hubble-fgs.conf.d/"

	adminTgConfDir    = "/etc/tetragon/"
	adminTgConfDropIn = "/etc/tetragon/tetragon.conf.d/"

	// These we ship them
	packageTgConfDropIns = []string{
		"/usr/lib/tetragon/tetragon.conf.d/",
		"/usr/local/lib/tetragon/tetragon.conf.d/",
	}

	// If both /etc/hubble-fgs and /etc/tetragon/ contain files then report an error
	errConfigBoth = fmt.Errorf("both %s and %s exist and contain configurations", oldAdminFgsConfDir, adminTgConfDir)
)

// validateEnv() check environment variables for FGS_ and TETRAGON_
//
// Returns:
//
//	On success returns bool, true if only TETRAGON_ env vars are being used,
//	       or false if only FGS_ env vars are being used.
//	       If related env vars are not set, then return true to indicate we
//	       want to default to TETRAGON_.
//	On failures an error is returned. Having both TETRAGON_ and FGS_ is considered
//	       an error.
func validateEnv() (bool, error) {
	envs := os.Environ()
	fgs, tetragon := "", ""
	for _, v := range envs {
		s := strings.SplitN(v, "=", 2)
		if strings.HasPrefix(s[0], "FGS_") {
			fgs = s[0]
			// Warn users about using old environment variable prefix  FGS_
			log.Warnf("Environment variable with a prefix  FGS_  '%q'  has been deprecated, please use  TETRAGON_  prefix instead", fgs)
			tgenv := strings.Replace(fgs, "FGS_", "TETRAGON_", 1)
			log.Warnf("Environment variable  '%q'  will take precedence over  '%q'", fgs, tgenv)
		}
		if strings.HasPrefix(s[0], "TETRAGON_") {
			tetragon = s[0]
		}
		// If both env are set return an error
		if fgs != "" && tetragon != "" {
			return false, fmt.Errorf("both environment variables are set: %q and %q", fgs, tetragon)
		}
	}

	if fgs != "" {
		return false, nil
	}

	return true, nil
}

// validateConfig() checks both /etc/hubble-fgs/ and /etc/tetragon/ for configurations
//
// Returns:
//
//	On success returns bool, true to indicate /etc/tetragon/tetragon.conf.d/ should be used,
//	            false to indicate if /etc/hubble-fgs/hubble-fgs.conf.d/ should be used.
//	On failures an error is returned. Having both /etc/tetragon/tetragon.conf.d/ and
//		    /etc/hubble-fgs/hubble-fgs.conf.d/ contain configurations is an error.
func validateConfig() (bool, error) {
	oldConfDirs, _ := os.ReadDir(oldAdminFgsConfDropIn)
	newConfDirs, _ := os.ReadDir(adminTgConfDropIn)

	// If the directory exists then that's fine since we had
	// scripts that created directories and maybe users's create
	// directories too, so we explicitly check if there are files inside
	// and if yes then we fail
	if len(newConfDirs) > 0 && len(oldConfDirs) > 0 {
		return false, errConfigBoth
	}

	oldConfYaml := false
	_, err := os.Stat(filepath.Join(oldAdminFgsConfDir, "hubble-fgs.yaml"))
	if err == nil {
		oldConfYaml = true
	}

	newConfYaml := false
	_, err = os.Stat(filepath.Join(adminTgConfDir, "tetragon.yaml"))
	if err == nil {
		newConfYaml = true
	}

	if newConfYaml && oldConfYaml {
		return false, errConfigBoth
	}

	if len(newConfDirs) > 0 && oldConfYaml == true ||
		len(oldConfDirs) > 0 && newConfYaml == true {
		return false, errConfigBoth
	}

	if len(oldConfDirs) > 0 || oldConfYaml {
		return false, nil
	}

	return true, nil
}

func readConfigFile(path string, file string) error {
	filePath := filepath.Join(path, file)
	st, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	if st.Mode().IsRegular() == false {
		return fmt.Errorf("failed to read config file '%s' not a regular file", file)
	}

	viper.AddConfigPath(path)
	err = viper.MergeInConfig()
	if err != nil {
		return err
	}

	return nil
}

func readConfigDir(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() == false {
		return fmt.Errorf("'%s' is not a directory", path)
	}

	cm, err := option.ReadDirConfig(path)
	if err != nil {
		return err
	}
	if err := viper.MergeConfigMap(cm); err != nil {
		return fmt.Errorf("merge config failed %v", err)
	}

	return nil
}

func readConfigSettings(newEnv bool, newConf bool, defaultConfDir string, defaultConfDropIn string, dropInsDir []string) {
	if newEnv == true {
		viper.SetEnvPrefix("tetragon")
	} else {
		viper.SetEnvPrefix("fgs")
	}
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	// First set default conf file and format
	if newConf == true {
		viper.SetConfigName("tetragon")
	} else {
		viper.SetConfigName("hubble-fgs")
	}
	viper.SetConfigType("yaml")

	// Read default drop-ins directories
	for _, dir := range dropInsDir {
		readConfigDir(dir)
	}

	// Look into cwd first, this is needed for quick development only
	readConfigFile(".", "tetragon.yaml")

	if newConf == true {
		readConfigFile(defaultConfDir, "tetragon.yaml")
	} else {
		// Look for /etc/hubble-fgs/hubble-fgs.yaml
		readConfigFile(defaultConfDir, "hubble-fgs.yaml")
	}

	// Look into default /etc/hubble-fgs/hubble-fgs.conf.d/ now
	readConfigDir(defaultConfDropIn)

	// Read now the passed key --config-dir
	if viper.IsSet(keyConfigDir) {
		configDir := viper.GetString(keyConfigDir)
		// viper.IsSet could return true on an empty string reset
		if configDir != "" {
			err := readConfigDir(configDir)
			if err != nil {
				log.WithField(keyConfigDir, configDir).WithError(err).Fatal("Failed to read config from directory")
			} else {
				log.WithField(keyConfigDir, configDir).Info("Loaded config from directory")
			}
		}
	}
}
