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

func getLogLevel() logrus.Level {
	if level, ok := strToLogrusLevel[viper.GetString("log-level")]; ok {
		return level
	} else if viper.GetBool("debug") {
		return logrus.DebugLevel
	}
	return logrus.InfoLevel
}

// GetLogger returns the logger properly set up accordingly with the debug flag.
func GetLogger() logrus.FieldLogger {
	once.Do(func() {
		log = logrus.New()
		log.SetLevel(getLogLevel())
	})
	return log
}
