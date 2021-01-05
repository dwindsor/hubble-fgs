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
package sysdump

import (
	"bytes"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestMultiLog(t *testing.T) {

	fmt := logrus.TextFormatter{
		DisableColors:    true,
		DisableTimestamp: true,
	}

	log1 := logrus.New()
	buff1 := new(bytes.Buffer)
	log1.Out = buff1
	log1.SetLevel(logrus.InfoLevel)
	log1.SetFormatter(&fmt)

	log2 := logrus.New()
	buff2 := new(bytes.Buffer)
	log2.Out = buff2
	log2.SetLevel(logrus.WarnLevel)
	log2.SetFormatter(&fmt)

	multiLog := MultiLog{
		Logs: []logrus.FieldLogger{log1, log2},
	}

	multiLog.Info("foo")
	multiLog.Warn("bar")
	expected1 := "level=info msg=foo\nlevel=warning msg=bar\n"
	if buff1.String() != expected1 {
		t.Errorf("Expected:\n%s\nbut got:\n%s\n", expected1, buff1.String())
	}

	expected2 := "level=warning msg=bar\n"
	if buff2.String() != expected2 {
		t.Errorf("Expected:\n%s\nbut got:\n%s\n", expected2, buff2.String())
	}

	t.Log("Success")
}
