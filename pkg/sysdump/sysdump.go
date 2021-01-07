// Copyright 2020-2021 Authors of Hubble
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

// FGS sysdump code

package sysdump

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/defaults"
	"github.com/covalentio/hubble-fgs/pkg/logger"

	"github.com/sirupsen/logrus"
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

type sysdumpInfo struct {
	info      *InitInfo
	prefixDir string
	multiLog  MultiLog
}

func doTarAddBuff(tarWriter *tar.Writer, fname string, buff *bytes.Buffer) error {
	logHdr := tar.Header{
		Typeflag: tar.TypeReg,
		Name:     fname,
		Size:     int64(buff.Len()),
		Mode:     0644,
	}

	if err := tarWriter.WriteHeader(&logHdr); err != nil {
		logger.GetLogger().Error("failed to write log buffer tar header")
	}

	_, err := io.Copy(tarWriter, buff)
	if err != nil {
		logger.GetLogger().Error("failed to copy log buffer")
	}
	return err
}

func (s *sysdumpInfo) tarAddBuff(tarWriter *tar.Writer, fname string, buff *bytes.Buffer) error {
	name := filepath.Join(s.prefixDir, fname)
	return doTarAddBuff(tarWriter, name, buff)
}

func (s *sysdumpInfo) tarAddFile(tarWriter *tar.Writer, fnameSrc string, fnameDst string) error {
	fileSrc, err := os.Open(fnameSrc)
	if err != nil {
		s.multiLog.WithField("path", fnameSrc).Warn("failed to open file")
		return err
	}
	defer fileSrc.Close()

	fileSrcInfo, err := fileSrc.Stat()
	if err != nil {
		s.multiLog.WithField("path", fnameSrc).Warn("failed to stat file")
		return err
	}

	hdr, err := tar.FileInfoHeader(fileSrcInfo, "" /* unused link target */)
	if err != nil {
		s.multiLog.Warn("error creating tar header")
		return err
	}
	hdr.Name = filepath.Join(s.prefixDir, fnameDst)

	if err := tarWriter.WriteHeader(hdr); err != nil {
		s.multiLog.Warn("failed to write tar header")
		return err
	}

	_, err = io.Copy(tarWriter, fileSrc)
	if err != nil {
		s.multiLog.WithField("fnameSrc", fnameSrc).Warn("error copying data from source file")
		return err
	}

	return nil
}

// Sysdump performs a sysdump and writes results as a tar archive in the given filename
func Sysdump(outFname string) error {
	info, err := LoadInitInfo()
	if err != nil {
		return err
	}

	return doSysdump(info, outFname)
}

func doSysdump(info *InitInfo, outFname string) error {
	// we log into two logs, one is the standard one and another one is a
	// buffer that we are going to include as a file into the sysdump.
	sysdumpLogger := logrus.New()
	logBuff := new(bytes.Buffer)
	sysdumpLogger.Out = logBuff
	logrus.SetLevel(logrus.InfoLevel)
	multiLog := MultiLog{
		Logs: []logrus.FieldLogger{
			logger.GetLogger(),
			sysdumpLogger,
		},
	}
	prefixDir := fmt.Sprintf("hubble-enterprise-sysdump-%s", time.Now().Format("20060102150405"))

	outFile, err := os.Create(outFname)
	if err != nil {
		multiLog.WithField("tarFile", outFname).Warn("failed to sysdump tarfile")
		return err
	}
	defer outFile.Close()

	si := sysdumpInfo{
		info:      info,
		prefixDir: prefixDir,
		multiLog:  multiLog,
	}

	tarWriter := tar.NewWriter(outFile)
	defer func() {
		defer tarWriter.Close()
		si.tarAddBuff(tarWriter, "hubble-enterprise-sysdump.log", logBuff)
	}()

	si.addInitInfo(tarWriter)
	si.addLibFiles(tarWriter)
	si.addBtfFile(tarWriter)
	si.addFgsLog(tarWriter)
	si.addMetrics(tarWriter)
	return nil
}

func (s *sysdumpInfo) addInitInfo(tarWriter *tar.Writer) error {
	s.multiLog.Info("saving init info")
	buff := new(bytes.Buffer)
	if err := json.NewEncoder(buff).Encode(s.info); err != nil {
		s.multiLog.Warn("failed to serialze init info")
		return err
	}
	return s.tarAddBuff(tarWriter, "fgs-info.json", buff)
}

// addLibFiles adds all files under the hubble lib directory to the archive.
//
// Currently, this includes the bpf files and potentially the btf file if it is stored there.  If
// there are files that we do not want to add, we can filter them out, but for now we can just grab
// everything.
func (s *sysdumpInfo) addLibFiles(tarWriter *tar.Writer) error {
	s.multiLog.WithField("libDir", s.info.LibDir).Info("retrieving lib directory")
	return filepath.Walk(
		s.info.LibDir,
		// NB: if the walk function returns an error, the walk terminates.
		// We want to gather as much information as possible, so we
		// never return an error.
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error walking path.")
				return nil
			}

			// We ignore non-regular files.
			// Note that this also includes symbolic links. We could be smarter about
			// symlinks if they point within the directory we are archiving, but since
			// we do not use them, there is currently no reason for the complexity.
			mode := info.Mode()
			if !(mode.IsRegular() || mode.IsDir()) {
				s.multiLog.WithField("path", path).Warn("not a regular file, ignoring")
				return nil
			}

			hdr, err := tar.FileInfoHeader(info, "" /* unused link target */)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error creating tar header")
				return nil
			}
			// fix filename
			hdr.Name = filepath.Join(s.prefixDir, "lib", strings.TrimPrefix(path, s.info.LibDir))

			if err := tarWriter.WriteHeader(hdr); err != nil {
				s.multiLog.WithField("path", path).Warn("failed to write tar header")
				return nil
			}

			if info.IsDir() {
				return nil
			}

			// open and copy file to the tar archive
			file, err := os.Open(path)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error opening file")
				return nil
			}
			defer file.Close()
			_, err = io.Copy(tarWriter, file)
			if err != nil {
				s.multiLog.WithField("path", path).Warn("error copying data from file")
				return nil
			}
			return nil
		})
}

// addBtfFile adds the btf file to the archive.
func (s *sysdumpInfo) addBtfFile(tarWriter *tar.Writer) error {
	btfFname, err := filepath.EvalSymlinks(s.info.BtfFname)
	if err != nil {
		s.multiLog.WithField("btfFname", s.info.BtfFname).Warnf("error resolving btf file: %s", err)
		return err
	}

	if rel, err := filepath.Rel(s.info.LibDir, btfFname); err == nil {
		s.multiLog.WithField("btfFname", s.info.BtfFname).Infof("btf file already in lib dir: %s", rel)
		return nil
	}

	err = s.tarAddFile(tarWriter, btfFname, "btf")
	if err == nil {
		s.multiLog.WithField("btfFname", s.info.BtfFname).Info("btf file added")
	}
	return err
}

// addFgsLog adds the fgs log file to the archive
func (s *sysdumpInfo) addFgsLog(tarWriter *tar.Writer) error {
	if s.info.ExportFname == "" {
		s.multiLog.Info("no export file specified")
		return nil
	}

	err := s.tarAddFile(tarWriter, s.info.ExportFname, "hubble-fgs.log")
	if err == nil {
		s.multiLog.WithField("exportFname", s.info.ExportFname).Info("fgs log file added")
	}
	return err
}

// addMetrics adds the output of metrics in the tar file
func (s *sysdumpInfo) addMetrics(tarWriter *tar.Writer) error {
	// nothing to do if metrics server is not running
	if s.info.MetricsAddr == "" {
		return nil
	}

	// determine the port that the metrics server listens to
	slice := strings.Split(s.info.MetricsAddr, ":")
	if len(slice) < 2 {
		s.multiLog.WithField("metricsAddr", s.info.MetricsAddr).Warn("could not determine metrics port")
		return errors.New("failed to determine metrics port")
	}
	port := slice[len(slice)-1]

	// contact metrics server
	metricsAddr := fmt.Sprintf("http://localhost:%s/metrics", port)
	s.multiLog.WithField("metricsAddr", metricsAddr).Info("contacting metrics server")
	resp, err := http.Get(metricsAddr)
	if err != nil {
		s.multiLog.WithField("metricsAddr", metricsAddr).WithField("err", err).Warn("failed to contact metrics server")
		return err
	}
	defer resp.Body.Close()

	buff := new(bytes.Buffer)
	if _, err = buff.ReadFrom(resp.Body); err != nil {
		s.multiLog.Warn("error in reading metrics server response: %s", err)
	}
	return s.tarAddBuff(tarWriter, "metrics", buff)
}
