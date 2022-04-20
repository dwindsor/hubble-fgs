//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package eventcache

import (
	"fmt"

	"github.com/isovalent/hubble-fgs/cmd/protoc-gen-go-fgs/common"
	"google.golang.org/protobuf/compiler/protogen"
)

// getEventsResponse generates a new GetEventsResponse_<EVENT_TYPE>
func doGetEventsResponse(g *protogen.GeneratedFile, eventType string) string {
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")
	subtype := common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", eventType))

	return fgsGER + `{
        Event: &` + subtype + `{` + eventType + `: e},
        NodeName: nodeName,
        Time: timestamp,
    }`
}

// doDestinationNames generates code for events that have DestinationNames,
// DestinationPod, and DestinationIp fields
func doDestinationNames(g *protogen.GeneratedFile, msg *protogen.Message) string {
	getPodInfoOfIp := common.GoIdent(g, "github.com/isovalent/hubble-fgs/pkg/podinfo", "GetPodInfoOfIp")
	parseIp := common.GoIdent(g, "net", "ParseIP")

	if hasDestinationFields(msg) {
		return `
            e.DestinationNames = labels
			if e.DestinationPod == nil {
				e.DestinationPod = ` + getPodInfoOfIp + `(` + parseIp + `(e.DestinationIp))
			}`
	}
	return ""
}

func generateDoHandleEvents(g *protogen.GeneratedFile, f *protogen.File) error {
	errorf := common.GoIdent(g, "fmt", "Errorf")

	fgsProcessInternal := common.GoIdent(g, "github.com/isovalent/hubble-fgs/pkg/process", "ProcessInternal")
	fgsGER := common.FgsApiIdent(g, "GetEventsResponse")
	timestamp := common.GoIdent(g, "google.golang.org/protobuf/types/known/timestamppb", "Timestamp")

	g.P(`func DoHandleEvent(event eventObj, internal *` + fgsProcessInternal + `, labels []string, nodeName string, timestamp *` + timestamp + `) (*` + fgsGER + `, error) {
        switch e := event.(type) {`)
	for _, msg := range f.Messages {
		if !isProcessEvent(msg) {
			continue
		}
		g.P(`
        case *` + g.QualifiedGoIdent(msg.GoIdent) + `:
            if internal != nil {
                e.Process = internal.GetProcessCopy()
            } else {
                ` + common.Logger(g) + `.WithField("event", e).Warn("Unable to set process information for event")
            }` + doDestinationNames(g, msg) + `
            return &` + doGetEventsResponse(g, msg.GoIdent.GoName) + `, nil`)
	}
	g.P(`}
            return nil, ` + errorf + `("DoHandleEvent: Unhandled event type %T", event)
        }`)

	return nil
}

func generateEventLabels(g *protogen.GeneratedFile, f *protogen.File) error {
	v1Endpoint := common.GoIdent(g, "github.com/cilium/hubble/pkg/api/v1", "Endpoint")

	g.P(`func DoEventLabels(endpoint *` + v1Endpoint + `, event eventObj) ([]string, *string) {
        var destinationIp string
        var labels []string

        switch e := event.(type) {`)
	for _, msg := range f.Messages {
		if !isProcessEvent(msg) || !hasDestinationFields(msg) {
			continue
		}
		g.P(`
        case *` + g.QualifiedGoIdent(msg.GoIdent) + `:
            destinationIp = e.GetDestinationIp()
            if len(e.DestinationNames) > 0 {
                return e.DestinationNames, nil
            }`)
	}
	g.P(`
        default:
            return labels, nil
        }
            return []string{}, &destinationIp
        }`)

	return nil
}

// Generate generates boilerplate code for the event cache
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "eventcache")

	fgsProcess := common.FgsApiIdent(g, "Process")

	g.P(`
        type eventObj interface {
            GetProcess() *` + fgsProcess + `
        }
    `)

	if err := generateDoHandleEvents(g, f); err != nil {
		return err
	}

	if err := generateEventLabels(g, f); err != nil {
		return err
	}

	return nil
}

// isProcessEvent returns true if the message is an FGS event that has a process field
func isProcessEvent(msg *protogen.Message) bool {
	if msg.Desc.Fields().ByName("process") != nil {
		return true
	}

	return false
}

func hasDestinationFields(msg *protogen.Message) bool {
	fields := make(map[string]struct{})

	for _, field := range msg.Fields {
		fields[field.GoName] = struct{}{}
	}

	_, hasDesinationNames := fields["DestinationNames"]
	_, hasDesinationPod := fields["DestinationPod"]
	_, hasDesinationIp := fields["DestinationIp"]

	if hasDesinationNames && hasDesinationPod && hasDesinationIp {
		return true
	}

	return false
}
