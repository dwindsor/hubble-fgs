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
package sttManager

import (
	"errors"
	"fmt"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	stt "github.com/isovalent/hubble-fgs/pkg/stacktracetree"
)

// StackTrace Tree Manager
type SttManagerHandle chan<- SttMgOp

// Operations

type SttMgCreateTree struct {
	TreeName string
	retChan  chan error
}

type SttMgDestroyTree struct {
	TreeName string
	retChan  chan error
}

type SttMgTreeInsert struct {
	TreeName   string
	Stacktrace *stt.Stt
	retChan    chan error
}

type SttMgTreeToProto struct {
	TreeName string
	RetChan  chan error
	RootNode *fgs.StackTraceNode
}

type SttMgStop struct {
	retChan chan error
}

// Not strictly needed but allows for better type checking.
type SttMgOp interface {
	SttMgOpDone(error)
}

// trivial SttMgOp implementations for commands
func (s *SttMgCreateTree) SttMgOpDone(e error)  { s.retChan <- e }
func (s *SttMgDestroyTree) SttMgOpDone(e error) { s.retChan <- e }
func (s *SttMgTreeInsert) SttMgOpDone(e error)  { s.retChan <- e }
func (s *SttMgTreeToProto) SttMgOpDone(e error) { s.RetChan <- e }
func (s *SttMgStop) SttMgOpDone(e error)        { s.retChan <- e }

func StartSttManager() SttManagerHandle {
	c := make(chan SttMgOp)
	treeMap := make(map[string]*stt.Sttree)
	go func() {
		done := false
		for !done {
			op_ := <-c
			err := errors.New("BUG in sttManager: unset error value")
			switch op := op_.(type) {
			case *SttMgCreateTree:
				treeMap[op.TreeName] = stt.CreateSttree()
				err = nil
			case *SttMgDestroyTree:
				delete(treeMap, op.TreeName)
				err = nil
			case *SttMgTreeInsert:
				stt, ok := treeMap[op.TreeName]
				if !ok {
					err = fmt.Errorf("SttMgTreeInsert: tree %s does not exist", op.TreeName)
					break
				}
				stt.AddStacktrace(op.Stacktrace)
				err = nil

			case *SttMgTreeToProto:
				stt, ok := treeMap[op.TreeName]
				if !ok {
					err = fmt.Errorf("SttMgTreeToProto: tree %s does not exist", op.TreeName)
					break
				}
				op.RootNode = stt.Root.ToProtoNode()
				err = nil

			case *SttMgStop:
				logger.GetLogger().Debugf("stopping tree manager...")
				done = true
				err = nil

			default:
				err = fmt.Errorf("unknown sensorOp: %v", op)
			}

			op_.SttMgOpDone(err)
		}
	}()

	return c
}

func (h SttManagerHandle) CreateTree(tname string) error {
	if h == nil {
		return fmt.Errorf("CreateTree failed, SttManagerHandle is nil")
	}

	retc := make(chan error)
	op := &SttMgCreateTree{
		TreeName: tname,
		retChan:  retc,
	}
	h <- op
	return <-retc
}

func (h SttManagerHandle) DestroyTree(tname string) error {
	if h == nil {
		return fmt.Errorf("DestroyTree failed, SttManagerHandle is nil")
	}

	retc := make(chan error)
	op := &SttMgDestroyTree{
		TreeName: tname,
		retChan:  retc,
	}
	h <- op
	return <-retc
}

func (h SttManagerHandle) Insert(tname string, stt *stt.Stt) error {
	if h == nil {
		return fmt.Errorf("Instert failed, SttManagerHandle is nil")
	}

	retc := make(chan error)
	op := &SttMgTreeInsert{
		TreeName:   tname,
		Stacktrace: stt,
		retChan:    retc,
	}
	h <- op
	return <-retc
}
