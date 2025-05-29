package ocsf

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/isovalent/ipa/ocsf/v1alpha"
)

func processToOCSF(p *tetragon.Process) *v1alpha.Process {
	pid := int32(p.Pid.GetValue())
	auid := int32(p.Auid.GetValue())

	createdTimeString := p.StartTime.AsTime().Format(time.RFC3339)
	createdTime := p.StartTime.AsTime().UnixMilli()

	return &v1alpha.Process{
		Auid:             &auid,
		CmdLine:          &p.Arguments,
		CreatedTime:      &createdTime,
		CreatedTimeDt:    &createdTimeString,
		Path:             &p.Binary,
		Pid:              &pid,
		WorkingDirectory: &p.Cwd,
	}
}

func processConnectToOCSFActor(pc *tetragon.ProcessConnect) *v1alpha.Actor {
	process := processToOCSF(pc.Process)
	process.ParentProcess = processToOCSF(pc.Parent)
	return &v1alpha.Actor{
		Process: process,
	}
}

func processConnectToOCSFConnectInformation(pc *tetragon.ProcessConnect) *v1alpha.NetworkConnectionInformation {
	dirId := v1alpha.NetworkConnectionInformationDirectionID_NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_OUTBOUND
	dir := v1alpha.NetworkConnectionInformationDirectionID_name[int32(dirId)]
	protoId := int32(pc.Protocol)
	protoName := tetragon.SocketProtocol_name[protoId]
	protoVerId := v1alpha.NetworkConnectionInformationProtocolVersionID_NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_4
	protoVerName := v1alpha.NetworkConnectionInformationProtocolVersionID_name[int32(protoVerId)]

	return &v1alpha.NetworkConnectionInformation{
		Direction:    &dir,
		DirectionId:  dirId,
		ProtocolName: &protoName,
		ProtocolNum:  &protoId,
		ProtocolVer:  &protoVerName,
	}
}

func processConnectToOCSFDestination(pc *tetragon.ProcessConnect) *v1alpha.NetworkEndpoint {
	port := int32(pc.DestinationPort.GetValue())
	names := ""
	// For OCSF just pick the first name
	if len(pc.DestinationNames) > 0 {
		names = pc.DestinationNames[0]
	}
	return &v1alpha.NetworkEndpoint{
		Hostname: &names,
		Ip:       &pc.DestinationIp,
		Port:     &port,
	}
}

func processConnectToOCSFSource(pc *tetragon.ProcessConnect) *v1alpha.NetworkEndpoint {
	srcPort := int32(pc.SourcePort.GetValue())
	return &v1alpha.NetworkEndpoint{
		Ip:   &pc.SourceIp,
		Port: &srcPort,
	}
}

func processConnectToOCSF(pc *tetragon.ProcessConnect) *v1alpha.EndpointEvent_NetworkActivityDetail {
	categoryId := v1alpha.CategoryID_CATEGORY_ID_NETWORK_ACTIVITY
	categoryName := v1alpha.CategoryID_name[int32(categoryId)]

	classId := v1alpha.ClassID_CLASS_ID_NETWORK_ACTIVITY
	className := v1alpha.ClassID_name[int32(classId)]

	activityId := v1alpha.NetworkActivityActivityID(v1alpha.NetworkActivityActivityID_NETWORK_ACTIVITY_ACTIVITY_ID_OPEN)
	activityString := v1alpha.NetworkActivityActivityID_name[int32(activityId)]

	actor := processConnectToOCSFActor(pc)
	connectionInfo := processConnectToOCSFConnectInformation(pc)
	destination := processConnectToOCSFDestination(pc)
	source := processConnectToOCSFSource(pc)

	statusId := v1alpha.BaseEventStatusID_BASE_EVENT_STATUS_ID_SUCCESS
	status := v1alpha.BaseEventStatusID_name[int32(statusId)]

	typeName := activityString + className
	typeId := int64(classId) + int64(activityId)

	na := &v1alpha.NetworkActivity{
		ActivityId:     &activityId,
		ActivityName:   &activityString,
		Actor:          actor,
		CategoryName:   &categoryName,
		CategoryUid:    categoryId,
		ClassName:      &className,
		ClassUid:       classId,
		ConnectionInfo: connectionInfo,
		DstEndpoint:    destination,
		SrcEndpoint:    source,
		Status:         &status,
		StatusId:       &statusId,
		TypeName:       &typeName,
		TypeUid:        typeId,
	}

	return &v1alpha.EndpointEvent_NetworkActivityDetail{
		NetworkActivityDetail: na,
	}
}

func ResponseToOCSF(response *tetragon.GetEventsResponse) (*v1alpha.EndpointEvent, bool) {
	n := processConnectToOCSF(response.GetProcessConnect())
	res := &v1alpha.EndpointEvent{
		Detail: n,
	}
	return res, true
}
