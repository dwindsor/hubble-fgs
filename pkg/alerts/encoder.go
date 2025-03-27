//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package alerts

import (
	"io"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type jsonEncoder struct {
	writer io.WriteCloser
	fname  string
	refCnt int32
	mu     sync.Mutex
}

func newJsonEncoder(w io.WriteCloser, fname string) *jsonEncoder {
	return &jsonEncoder{
		writer: w,
		fname:  fname,
		refCnt: 1,
	}
}

func (e *jsonEncoder) IncRef() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refCnt++
}

func (e *jsonEncoder) DecRef() int32 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refCnt--
	if e.refCnt == 0 {
		e.writer.Close()
	}
	return e.refCnt
}

func (e *jsonEncoder) encode(alert *tetragon.Alert) error {
	out, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(alert)
	if err != nil {
		return err
	}

	// let's take a lock, this will ensure that writes are atomic
	e.mu.Lock()
	defer e.mu.Unlock()

	// encoder is closed, nothing to do
	if e.refCnt == 0 {
		return nil
	}
	out = append(out, '\n')
	_, err = e.writer.Write(out)
	if err != nil {
		return err
	}
	return nil
}
