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

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type jsonEncoder struct {
	writer io.WriteCloser
}

func (e *jsonEncoder) encode(alert *tetragon.Alert) error {
	out, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(alert)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	_, err = e.writer.Write(out)
	if err != nil {
		return err
	}

	return nil
}
