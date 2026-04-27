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
	"runtime"
	"time"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/version"
	"github.com/google/uuid"
	"github.com/isovalent/ipa/ocsf/v1alpha"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func processToOCSF(p *tetragon.Process) *v1alpha.Process {
	return &v1alpha.Process{
		Auid:             new(int32(p.Auid.GetValue())),
		CmdLine:          &p.Arguments,
		CreatedTime:      new(p.StartTime.AsTime().UnixMilli()),
		CreatedTimeDt:    new(p.StartTime.AsTime().Format(time.RFC3339Nano)),
		Path:             &p.Binary,
		Pid:              new(int32(p.Pid.GetValue())),
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
	protoId := int32(pc.Protocol)
	protoVerId := v1alpha.NetworkConnectionInformationProtocolVersionID_NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_4
	return &v1alpha.NetworkConnectionInformation{
		Direction:    new(v1alpha.NetworkConnectionInformationDirectionID_name[int32(dirId)]),
		DirectionId:  dirId,
		ProtocolName: new(tetragon.SocketProtocol_name[protoId]),
		ProtocolNum:  &protoId,
		ProtocolVer:  new(v1alpha.NetworkConnectionInformationProtocolVersionID_name[int32(protoVerId)]),
	}
}

func processConnectToOCSFDestination(pc *tetragon.ProcessConnect) *v1alpha.NetworkEndpoint {
	names := ""
	// For OCSF just pick the first name
	if len(pc.DestinationNames) > 0 {
		names = pc.DestinationNames[0]
	}
	return &v1alpha.NetworkEndpoint{
		Hostname: &names,
		Ip:       &pc.DestinationIp,
		Port:     new(int32(pc.DestinationPort.GetValue())),
	}
}

func processConnectToOCSFSource(pc *tetragon.ProcessConnect) *v1alpha.NetworkEndpoint {
	return &v1alpha.NetworkEndpoint{
		Ip:   &pc.SourceIp,
		Port: new(int32(pc.SourcePort.GetValue())),
	}
}

func getAgent() *v1alpha.Agent {
	agentTypeId := v1alpha.AgentTypeID_AGENT_TYPE_ID_OTHER
	return &v1alpha.Agent{
		Name:       new("Isovalent Tetragon"),
		Type:       new(v1alpha.AgentTypeID_name[int32(agentTypeId)]),
		TypeId:     &agentTypeId,
		Uid:        new(version.Version),
		VendorName: new("Isovalent Cisco"),
	}
}

func getOS() *v1alpha.OperatingSystemOS {
	_, verStr, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return &v1alpha.OperatingSystemOS{
		KernelRelease: &verStr,
		Name:          "Linux",
		TypeId:        200,
	}
}

func getHwInfo() *v1alpha.DeviceHardwareInfo {
	id := v1alpha.DeviceHardwareInfoCPUArchitectureID_DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_UNKNOWN
	if runtime.GOARCH == "amd64" || runtime.GOARCH != "x86_64" {
		id = v1alpha.DeviceHardwareInfoCPUArchitectureID_DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_X86
	} else {
		id = v1alpha.DeviceHardwareInfoCPUArchitectureID_DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_ARM
	}
	return &v1alpha.DeviceHardwareInfo{
		CpuArchitecture:   new(runtime.GOARCH),
		CpuArchitectureId: &id,
		CpuBits:           new(int32(64)),
	}
}

func getDevice() *v1alpha.Device {
	agent := getAgent()
	agents := []*v1alpha.Agent{agent}
	os := getOS()
	hw := getHwInfo()

	return &v1alpha.Device{
		AgentList: agents,
		Hostname:  new(node.GetNodeNameForExport()),
		HwInfo:    hw,
		Os:        os,
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
	return &v1alpha.Product{
		Name:       new("Tetragon"),
		VendorName: new("Isovalent"),
		Version:    new(version.Version),
	}
}

func linuxProfile() []string {
	return []string{"host", "security_control", "datetime", "linux/linux_users"}
}

func processConnectToOCSF(pc *tetragon.ProcessConnect, t *timestamppb.Timestamp) *v1alpha.EndpointEvent_NetworkActivityDetail {
	categoryId := v1alpha.CategoryID_CATEGORY_ID_NETWORK_ACTIVITY
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
	typeId := int64(classId) + int64(activityId)

	id, _ := uuid.NewV7()
	ext := linuxExtension()
	prod := tetragonProduct()
	profile := linuxProfile()

	metadata := &v1alpha.Metadata{
		Extensions:   ext,
		Product:      prod,
		Profiles:     profile,
		Uid:          new(id.String()),
		LoggedTimeDt: new(timestamppb.Now().AsTime().Format(time.RFC3339Nano)),
	}

	networkActivitySeverityId := v1alpha.BaseEventSeverityID_BASE_EVENT_SEVERITY_ID_INFORMATIONAL

	na := &v1alpha.NetworkActivity{
		ActivityId:     &activityId,
		ActivityName:   &activityString,
		Actor:          actor,
		CategoryName:   new(v1alpha.CategoryID_name[int32(categoryId)]),
		CategoryUid:    categoryId,
		ClassName:      &className,
		ClassUid:       classId,
		ConnectionInfo: connectionInfo,
		Device:         device,
		DstEndpoint:    destination,
		Metadata:       metadata,
		Severity:       new("Informational"),
		SeverityId:     networkActivitySeverityId,
		SrcEndpoint:    source,
		Status:         new(v1alpha.BaseEventStatusID_name[int32(statusId)]),
		StatusId:       &statusId,
		TypeName:       new(activityString + className),
		TypeUid:        typeId,
		TimeDt:         new(t.AsTime().Format(time.RFC3339Nano)),
	}

	return &v1alpha.EndpointEvent_NetworkActivityDetail{
		NetworkActivityDetail: na,
	}
}

func ResponseToOCSF(response *tetragon.GetEventsResponse) *v1alpha.EndpointEvent_NetworkActivityDetail {
	n := processConnectToOCSF(response.GetProcessConnect(), response.Time)
	return n
}
