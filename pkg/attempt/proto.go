//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package attempt

import (
	api "github.com/cilium/tetragon/api/v1/tetragon"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a *Attempt) protoResult() *api.AttemptResult {
	if a.Result.err == nil {
		return &api.AttemptResult{
			Success: true,
		}
	}

	return &api.AttemptResult{
		Success: false,
		Error:   a.Result.err.Error(),
	}
}

func (a *Attempt) protoInfo() []*api.AttemptInfo {
	if a.Info == nil {
		return nil
	}

	ret := make([]*api.AttemptInfo, 0, len(a.Info))
	for _, ie := range a.Info {
		ret = append(ret, &api.AttemptInfo{
			Key: ie.Key,
			Val: ie.Val,
		})
	}

	return ret
}

func (a *Attempt) ToProto() *api.Attempt {
	ret := &api.Attempt{
		Op:       a.Op,
		Time:     timestamppb.New(a.Time),
		Duration: durationpb.New(a.Duration),
		Res:      a.protoResult(),
		Info:     a.protoInfo(),
	}

	for _, at := range a.Attempts {
		ret.Entries = append(ret.Entries, at.ToProto())
	}

	return ret
}

func (l *Attempts) protoEntries() []*api.Attempt {
	ret := make([]*api.Attempt, 0, len(l.Entries))
	for i := range l.Entries {
		ret = append(ret, l.Entries[i].ToProto())
	}
	return ret
}

func (l *Attempts) ToProto() *api.AttemptLog {
	return &api.AttemptLog{
		Total:    int32(l.Total),
		Failures: int32(l.Failures),
		Entries:  l.protoEntries(),
	}
}
