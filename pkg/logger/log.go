// Copyright 2019 Authors of Cilium
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

package logger

import (
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var (
	log  *logrus.Logger
	once sync.Once

	strToLogrusLevel = map[string]logrus.Level{
		"panic": logrus.PanicLevel,
		"fatal": logrus.FatalLevel,
		"error": logrus.ErrorLevel,
		"warn":  logrus.WarnLevel,
		"info":  logrus.InfoLevel,
		"debug": logrus.DebugLevel,
		"trace": logrus.TraceLevel,
	}
)

const (
	LogFormatTextId = iota
	LogFormatJsonId
)

var LogFormatOpts = [2]string{
	LogFormatTextId: "text",
	LogFormatJsonId: "json",
}

type LogFormatInvalidOpt struct {
	invalidOpt string
}

func (e *LogFormatInvalidOpt) Error() string {
	validOpts := strings.Join(LogFormatOpts[:], ",")
	return fmt.Sprintf("invalid format option: '%s', using text (valid options: %s)", e.invalidOpt, validOpts)
}

func getLogLevel() logrus.Level {
	if level, ok := strToLogrusLevel[viper.GetString("log-level")]; ok {
		return level
	} else if viper.GetBool("debug") {
		return logrus.DebugLevel
	}
	return logrus.InfoLevel
}

// getLogFormat returns the logrus.Formatter based on user-specified options.
//
// If the user options where invalid, it returns the default formatter and
// an appropriate error.
func getLogFormat() (logrus.Formatter, error) {
	logFormatOpt := viper.GetString("log-format")
	switch logFormatOpt {
	// Use the text formatter if --log-format flag is not specified.
	case LogFormatOpts[LogFormatTextId], "":
		return &logrus.TextFormatter{}, nil
	case LogFormatOpts[LogFormatJsonId]:
		return &logrus.JSONFormatter{}, nil
	default:
		return &logrus.TextFormatter{}, &LogFormatInvalidOpt{invalidOpt: logFormatOpt}
	}
}

// GetLogger returns the logger properly set up accordingly with the debug flag.
func GetLogger() logrus.FieldLogger {
	once.Do(func() {
		log = logrus.New()
		log.SetLevel(getLogLevel())
		fmt, err := getLogFormat()
		log.Formatter = fmt

		if err != nil {
			log.WithError(err).Warningf("invalid option")
		}
	})
	return log
}
