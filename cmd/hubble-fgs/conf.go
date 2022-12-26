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
	adminFgsConfDir       = "/etc/hubble-fgs/"
	adminFgsConfDropIn    = "/etc/hubble-fgs/hubble-fgs.conf.d/"
	packageFgsConfDropIns = []string{
		"/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
		"/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
	}
)

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

func readConfigSettings(defaultConfDir string, defaultConfDropIn string, dropInsDir []string) {
	viper.SetEnvPrefix("fgs")
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.AutomaticEnv()

	// First set default conf file and format
	viper.SetConfigName("hubble-fgs")
	viper.SetConfigType("yaml")

	// Read default drop-ins directories
	for _, dir := range dropInsDir {
		readConfigDir(dir)
	}

	// Look into cwd first, this is needed for quick development only
	readConfigFile(".", "hubble-fgs.yaml")

	// Look for /etc/hubble-fgs/hubble-fgs.yaml
	readConfigFile(defaultConfDir, "hubble-fgs.yaml")

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
