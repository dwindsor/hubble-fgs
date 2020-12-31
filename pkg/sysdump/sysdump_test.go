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
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {

	tmpFile, err := ioutil.TempFile(os.TempDir(), "fgs-sysdump-test-")
	if err != nil {
		t.Error("failed to create temporary file")
	}
	defer os.Remove(tmpFile.Name())

	info1 := InitInfo{
		ExportFname: "1",
		LibDir:      "2",
		BtfFname:    "3",
		ServerAddr:  "",
		MetricsAddr: "foo",
	}

	if err := doSaveInitInfo(tmpFile.Name(), &info1); err != nil {
		t.Errorf("failed to save info: %s", err)
	}

	info2, err := doLoadInitInfo(tmpFile.Name())
	if err != nil {
		t.Errorf("failed to load info: %s", err)
	}

	if !reflect.DeepEqual(&info1, info2) {
		t.Errorf("mismatching structures: %s vs %s", info1, info2)
	}

	t.Log("Success")
}
