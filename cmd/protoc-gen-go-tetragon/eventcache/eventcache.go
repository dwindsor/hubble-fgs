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
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	"google.golang.org/protobuf/compiler/protogen"
)

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

func generateEventLabels(g *protogen.GeneratedFile, f *protogen.File) error {
	v1Endpoint := common.GoIdent(g, "github.com/cilium/hubble/pkg/api/v1", "Endpoint")

	g.P(`func DoEventLabels(endpoint *` + v1Endpoint + `, event eventObj) ([]string, *string) {
        var destinationIp string
        var labels []string

        switch e := event.(type) {`)
	for _, msg := range f.Messages {
		if !common.IsProcessEvent(msg) || !hasDestinationFields(msg) {
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
	g := common.NewGeneratedFile(gen, f, "eventcacheenterprise")

	fgsProcess := common.TetragonApiIdent(g, "Process")

	g.P(`
        type eventObj interface {
            GetProcess() *` + fgsProcess + `
        }
    `)

	if err := generateEventLabels(g, f); err != nil {
		return err
	}

	return nil
}
