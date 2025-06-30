package ocsf

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/google/uuid"
	"github.com/isovalent/ipa/ocsf/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func getAgent() *v1alpha.Agent {
	tetragonName := "Isovalent Tetragon"
	tetragonVendor := "Isovalent Cisco"
	tetragonVersion := version.Version

	agentTypeId := v1alpha.AgentTypeID_AGENT_TYPE_ID_OTHER
	agentType := v1alpha.AgentTypeID_name[int32(agentTypeId)]

	return &v1alpha.Agent{
		Name:       &tetragonName,
		Type:       &agentType,
		TypeId:     &agentTypeId,
		Uid:        &tetragonVersion,
		VendorName: &tetragonVendor,
	}
}

func getDevice() *v1alpha.Device {
	agent := getAgent()
	agents := []*v1alpha.Agent{agent}
	hostname := node.GetNodeNameForExport()

	return &v1alpha.Device{
		AgentList: agents,
		Hostname:  &hostname,
	}
}

func linuxExtension() []*v1alpha.SchemaExtension {
	return []*v1alpha.SchemaExtension{
		&v1alpha.SchemaExtension{
			Name:    "linux",
			Uid:     "1",
			Version: "1.4.0",
		},
	}
}

func tetragonProduct() *v1alpha.Product {
	name := "Tetragon"
	vendor := "Isovalent"
	version := version.Version

	return &v1alpha.Product{
		Name:       &name,
		VendorName: &vendor,
		Version:    &version,
	}
}

func linuxProfile() []string {
	return []string{"host", "security_control", "datetime", "linux/linux_users"}
}

func processConnectToOCSF(pc *tetragon.ProcessConnect, t *timestamppb.Timestamp) *v1alpha.EndpointEvent_NetworkActivityDetail {
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

	device := getDevice()

	statusId := v1alpha.BaseEventStatusID_BASE_EVENT_STATUS_ID_SUCCESS
	status := v1alpha.BaseEventStatusID_name[int32(statusId)]

	typeName := activityString + className
	typeId := int64(classId) + int64(activityId)

	timestamp := t.AsTime().Format(time.RFC3339)

	id, _ := uuid.NewV7()
	uid := id.String()
	now := timestamppb.Now().AsTime().Format(time.RFC3339)

	ext := linuxExtension()
	prod := tetragonProduct()
	profile := linuxProfile()

	metadata := &v1alpha.Metadata{
		Extensions:   ext,
		Product:      prod,
		Profiles:     profile,
		Uid:          &uid,
		LoggedTimeDt: &now,
	}

	networkActivitySeverity := "Informational"
	networkActivitySeverityId := v1alpha.BaseEventSeverityID_BASE_EVENT_SEVERITY_ID_INFORMATIONAL

	na := &v1alpha.NetworkActivity{
		ActivityId:     &activityId,
		ActivityName:   &activityString,
		Actor:          actor,
		CategoryName:   &categoryName,
		CategoryUid:    categoryId,
		ClassName:      &className,
		ClassUid:       classId,
		ConnectionInfo: connectionInfo,
		Device:         device,
		DstEndpoint:    destination,
		Metadata:       metadata,
		Severity:       &networkActivitySeverity,
		SeverityId:     networkActivitySeverityId,
		SrcEndpoint:    source,
		Status:         &status,
		StatusId:       &statusId,
		TypeName:       &typeName,
		TypeUid:        typeId,
		TimeDt:         &timestamp,
	}

	return &v1alpha.EndpointEvent_NetworkActivityDetail{
		NetworkActivityDetail: na,
	}
}

func ResponseToOCSF(response *tetragon.GetEventsResponse) *v1alpha.EndpointEvent_NetworkActivityDetail {
	n := processConnectToOCSF(response.GetProcessConnect(), response.Time)
	return n
}
