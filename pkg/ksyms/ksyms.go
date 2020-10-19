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
//

package ksyms

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ksym struct {
	addr uint64
	name string
	ty   string
}

// Ksyms is a structure for kernel symbols
type Ksyms struct {
	table []ksym
}

// FnOffset is a function location (function name + offset)
type FnOffset struct {
	SymName string
	Offset  uint64
}

// ToString returns a string representation of FnOffset
func (fo *FnOffset) ToString() string {
	return fmt.Sprintf("%s()+0x%x", fo.SymName, fo.Offset)
}

func (ksym *ksym) isFunction() bool {
	tyLow := strings.ToLower(ksym.ty)
	return tyLow == "w" || tyLow == "t"
}

// NewKsyms creates a new Ksyms structure (by reading procfs/kallsyms)
func NewKsyms(procfs string) (*Ksyms, error) {
	kallsymsFname := fmt.Sprintf("%s/kallsyms", procfs)
	file, err := os.Open(kallsymsFname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = nil
	var ksyms Ksyms
	s := bufio.NewScanner(file)
	needsSort := false

	for s.Scan() {
		txt := s.Text()
		fields := strings.Fields(txt)
		var sym ksym

		if len(fields) < 3 {
			fmt.Fprintf(os.Stderr, "Failed to parse: '%s'\n", txt)
			continue
		}

		if sym.addr, err = strconv.ParseUint(fields[0], 16, 64); err != nil {
			err = fmt.Errorf("failed to parse address: %v", err)
			break
		}
		sym.ty = fields[1]
		sym.name = fields[2]

		//fmt.Printf("%s => %d %s\n", txt, sym.addr, sym.name)
		if sym.isFunction() && sym.addr == 0 {
			err = fmt.Errorf("function %s reported at address 0. Insuffcient permissions?", sym.name)
			break
		}

		if !needsSort && len(ksyms.table) > 0 {
			lastSym := ksyms.table[len(ksyms.table)-1]
			if lastSym.addr > sym.addr {
				needsSort = true
			}
		}

		ksyms.table = append(ksyms.table, sym)
	}

	if err == nil {
		err = s.Err()
	}

	if err != nil && len(ksyms.table) == 0 {
		err = errors.New("No synmbols found")
	}

	if err != nil {
		return nil, err
	}

	if needsSort {
		sort.Slice(ksyms.table[:], func(i1, i2 int) bool { return ksyms.table[i1].addr < ksyms.table[i2].addr })
	}

	return &ksyms, nil
}

// GetFnOffset -- returns the FnOffset for a given address
func (k *Ksyms) GetFnOffset(addr uint64) (*FnOffset, error) {

	// TODO: we can do binary search here if we care about performance
	i := 0
	for k.table[i].addr < addr {
		i++
	}

	if i == 0 {
		return nil, fmt.Errorf("address %d is before first sumbol %s@%d", addr, k.table[0].name, k.table[0].addr)
	}

	sym := k.table[i-1]
	if !sym.isFunction() {
		return nil, fmt.Errorf("Unable to find function for addr 0x%x", addr)
	}

	return &FnOffset{
		SymName: sym.name,
		Offset:  addr - sym.addr,
	}, nil
}
