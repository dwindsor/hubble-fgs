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

package stacktracetree

import (
	"fmt"
	"testing"
)

func TestSimple(t *testing.T) {
	fmt.Printf("Hello!\n")
	stt0 := Stt{}
	stt0.Append(0x10, nil, []SttLabel{})
	stt0.Append(0x20, nil, []SttLabel{})
	stt0.Append(0x30, nil, []SttLabel{})

	stt1 := Stt{}
	stt1.Append(0x10, nil, []SttLabel{})
	stt1.Append(0x20, nil, []SttLabel{})
	stt1.Append(0x40, nil, []SttLabel{})

	tree := CreateSttree()
	tree.AddStacktrace(&stt0)
	tree.Print()
	tree.AddStacktrace(&stt1)
	tree.Print()

}
