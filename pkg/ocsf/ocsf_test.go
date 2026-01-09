// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package ocsf

import (
	"testing"

	"github.com/isovalent/ipa/ocsf/v1alpha"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var (
	process = &tetragon.Process{
		Pid:       wrapperspb.UInt32(1),
		Auid:      wrapperspb.UInt32(2),
		StartTime: timestamppb.Now(),
		Binary:    "testing",
		Arguments: "args1 args2 args3",
		Cwd:       "/working/today",
	}
	parent = &tetragon.Process{
		Pid:       wrapperspb.UInt32(21),
		Auid:      wrapperspb.UInt32(22),
		StartTime: timestamppb.Now(),
		Binary:    "parents",
		Arguments: "parent1 parent2 parent3",
		Cwd:       "/working/parents",
	}
	processConnect = &tetragon.ProcessConnect{
		Process:          process,
		Parent:           parent,
		SourceIp:         "1.1.1.1",
		SourcePort:       wrapperspb.UInt32(22),
		DestinationIp:    "2.2.2.2",
		DestinationPort:  wrapperspb.UInt32(33),
		DestinationNames: []string{"testing.io", "fun.io"},
		Protocol:         tetragon.SocketProtocol_TCP,
	}
)

func TestProcess(t *testing.T) {
	ocsfProcess := processToOCSF(process)
	assert.Equal(t, *ocsfProcess.CmdLine, "args1 args2 args3")
	assert.Equal(t, *ocsfProcess.Path, "testing")
	assert.Equal(t, *ocsfProcess.WorkingDirectory, "/working/today")
	assert.Equal(t, *ocsfProcess.Auid, int32(2))
	assert.Equal(t, *ocsfProcess.Pid, int32(1))
}

func TestActor(t *testing.T) {
	ocsfActor := processConnectToOCSFActor(processConnect)
	assert.Equal(t, *ocsfActor.Process.CmdLine, "args1 args2 args3")
	assert.Equal(t, *ocsfActor.Process.Path, "testing")
	assert.Equal(t, *ocsfActor.Process.WorkingDirectory, "/working/today")
	assert.Equal(t, *ocsfActor.Process.Auid, int32(2))
	assert.Equal(t, *ocsfActor.Process.Pid, int32(1))
	assert.Equal(t, *ocsfActor.Process.ParentProcess.CmdLine, "parent1 parent2 parent3")
	assert.Equal(t, *ocsfActor.Process.ParentProcess.Path, "parents")
	assert.Equal(t, *ocsfActor.Process.ParentProcess.WorkingDirectory, "/working/parents")
	assert.Equal(t, *ocsfActor.Process.ParentProcess.Auid, int32(22))
	assert.Equal(t, *ocsfActor.Process.ParentProcess.Pid, int32(21))
}

func TestConnectInfo(t *testing.T) {
	ocsfConnInfo := processConnectToOCSFConnectInformation(processConnect)

	direction := "NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_OUTBOUND"
	tcp := "TCP"
	dirID := v1alpha.NetworkConnectionInformationDirectionID(2)
	protoNum := int32(6)
	protoVer := "NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_4"

	assert.Equal(t, ocsfConnInfo.Direction, &direction)
	assert.Equal(t, ocsfConnInfo.DirectionId, dirID)
	assert.Equal(t, ocsfConnInfo.ProtocolName, &tcp)
	assert.Equal(t, ocsfConnInfo.ProtocolNum, &protoNum)
	assert.Equal(t, ocsfConnInfo.ProtocolVer, &protoVer)
}

func TestDestination(t *testing.T) {
	destination := processConnectToOCSFDestination(processConnect)

	dstIp := "2.2.2.2"
	port := int32(33)
	host := "testing.io"

	assert.Equal(t, destination.Ip, &dstIp)
	assert.Equal(t, destination.Port, &port)
	assert.Equal(t, destination.Hostname, &host)
}

func TestSource(t *testing.T) {
	source := processConnectToOCSFSource(processConnect)

	srcIp := "1.1.1.1"
	port := int32(22)

	assert.Equal(t, source.Ip, &srcIp)
	assert.Equal(t, source.Port, &port)
}

func TestConnect(t *testing.T) {
	c := processConnectToOCSF(processConnect, timestamppb.Now())

	activityId := v1alpha.NetworkActivityActivityID(1)
	assert.Equal(t, *c.NetworkActivityDetail.ActivityId, activityId)
	assert.Equal(t, *c.NetworkActivityDetail.ActivityName, "NETWORK_ACTIVITY_ACTIVITY_ID_OPEN")

	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.CmdLine, "args1 args2 args3")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.Path, "testing")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.WorkingDirectory, "/working/today")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.Auid, int32(2))
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.Pid, int32(1))
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.ParentProcess.CmdLine, "parent1 parent2 parent3")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.ParentProcess.Path, "parents")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.ParentProcess.WorkingDirectory, "/working/parents")
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.ParentProcess.Auid, int32(22))
	assert.Equal(t, *c.NetworkActivityDetail.Actor.Process.ParentProcess.Pid, int32(21))

	assert.Equal(t, *c.NetworkActivityDetail.CategoryName, "CATEGORY_ID_NETWORK_ACTIVITY")
	assert.Equal(t, c.NetworkActivityDetail.CategoryUid, v1alpha.CategoryID(4))
	assert.Equal(t, *c.NetworkActivityDetail.ClassName, "CLASS_ID_NETWORK_ACTIVITY")
	assert.Equal(t, c.NetworkActivityDetail.ClassUid, v1alpha.ClassID(4001))

	dirID := v1alpha.NetworkConnectionInformationDirectionID(2)
	protoVer := "NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_4"
	assert.Equal(t, *c.NetworkActivityDetail.ConnectionInfo.Direction, "NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_OUTBOUND")
	assert.Equal(t, c.NetworkActivityDetail.ConnectionInfo.DirectionId, dirID)
	assert.Equal(t, *c.NetworkActivityDetail.ConnectionInfo.ProtocolName, "TCP")
	assert.Equal(t, *c.NetworkActivityDetail.ConnectionInfo.ProtocolNum, int32(6))
	assert.Equal(t, *c.NetworkActivityDetail.ConnectionInfo.ProtocolVer, protoVer)

	assert.Equal(t, *c.NetworkActivityDetail.DstEndpoint.Ip, "2.2.2.2")
	assert.Equal(t, *c.NetworkActivityDetail.DstEndpoint.Port, int32(33))
	assert.Equal(t, *c.NetworkActivityDetail.DstEndpoint.Hostname, "testing.io")

	assert.Equal(t, *c.NetworkActivityDetail.SrcEndpoint.Ip, "1.1.1.1")
	assert.Equal(t, *c.NetworkActivityDetail.SrcEndpoint.Port, int32(22))

	assert.Equal(t, *c.NetworkActivityDetail.Status, "BASE_EVENT_STATUS_ID_SUCCESS")
	assert.Equal(t, *c.NetworkActivityDetail.StatusId, v1alpha.BaseEventStatusID(1))
	assert.Equal(t, *c.NetworkActivityDetail.TypeName, "NETWORK_ACTIVITY_ACTIVITY_ID_OPENCLASS_ID_NETWORK_ACTIVITY")
	assert.Equal(t, c.NetworkActivityDetail.TypeUid, int64(4002))
}
