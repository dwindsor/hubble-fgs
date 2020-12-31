// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sysdump

import (
	"encoding/json"
	"os"

	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/logger"
)

const (
	// initInfoFile is the file location for the info file.
	// After initialization, initInfoFname will contain a json representation of InitInfo
	initInfoFname = defaults.DefaultRunDir + "fgs-info.json"
)

// InitInfo contains information about how FGS was initialized.
type InitInfo struct {
	ExportFname string `json:"export_fname"`
	LibDir      string `json:"lib_dir"`
	BtfFname    string `json:"btf_fname"`
	ServerAddr  string `json:"server_address"`
	MetricsAddr string `json:"metrics_address"`
}

// LoadInitInfo returns the InitInfo by reading the info file from its default location
func LoadInitInfo() (*InitInfo, error) {
	return doLoadInitInfo(initInfoFname)
}

// SaveInitInfo saves InitInfo to the info file
func SaveInitInfo(info *InitInfo) error {
	return doSaveInitInfo(initInfoFname, info)
}

func doLoadInitInfo(fname string) (*InitInfo, error) {
	f, err := os.Open(fname)
	if err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to open file")
		return nil, err
	}
	defer f.Close()

	var info InitInfo
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to read information from file")
		return nil, err
	}

	return &info, nil
}

func doSaveInitInfo(fname string, info *InitInfo) error {
	f, err := os.OpenFile(fname, os.O_WRONLY|os.O_CREATE, 0755)
	if err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to create file")
		return err
	}
	defer f.Close()

	if err := f.Truncate(0); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to truncate file")
		return err
	}

	if err := json.NewEncoder(f).Encode(info); err != nil {
		logger.GetLogger().WithField("infoFile", fname).Warn("failed to write information to file")
		return err
	}

	return nil
}
