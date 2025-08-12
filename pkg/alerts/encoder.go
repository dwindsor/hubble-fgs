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
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"

	"github.com/isovalent/hubble-fgs/pkg/metrics/alertmetrics"
)

type jsonEncoder struct {
	writer io.WriteCloser
	fname  string
	refCnt atomic.Int32
}

func newJsonEncoder(w io.WriteCloser, fname string) *jsonEncoder {
	// Wrap the WriteCloser with our byte counter to track exported bytes
	ret := &jsonEncoder{
		writer: alertmetrics.NewAlertExportedBytesCounterWriter(w),
		fname:  fname,
	}
	ret.refCnt.Store(1)
	return ret
}

func (e *jsonEncoder) IncRef() {
	e.refCnt.Add(1)
}

func (e *jsonEncoder) DecRef() int32 {
	refCnt := e.refCnt.Add(-1)
	if refCnt == 0 {
		e.writer.Close()
	}
	return refCnt
}

func (e *jsonEncoder) encode(alert *tetragon.Alert) error {
	out, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(alert)
	if err != nil {
		return err
	}

	// encoder is closed, nothing to do
	if e.refCnt.Load() == 0 {
		return nil
	}
	out = append(out, '\n')
	_, err = e.writer.Write(out)

	// only return an error if the encoder was not closed in the meantime
	if err != nil && e.refCnt.Load() > 0 {
		return err
	}
	return nil
}
