package ktime

import (
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func ToProto(ktime uint64) *timestamppb.Timestamp {
	return ToProtoOpt(ktime, true)
}

func ToProtoOpt(ktime uint64, monotonic bool) *timestamppb.Timestamp {
	decodedTime, err := reader.DecodeKtime(int64(ktime), monotonic)
	if err != nil {
		logrus.WithError(err).WithField("ktime", ktime).Warn("Failed to decode ktime")
		return timestamppb.Now()
	}
	return timestamppb.New(decodedTime)
}
