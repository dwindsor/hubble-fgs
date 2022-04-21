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

package filters

import (
	"fmt"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/isovalent/hubble-fgs/cmd/protoc-gen-go-fgs/common"
	"google.golang.org/protobuf/compiler/protogen"
)

func generateOpCodeForEventType(g *protogen.GeneratedFile, f *protogen.File) error {
	reflectType := common.GoIdent(g, "reflect", "Type")
	reflectTypeOf := common.GoIdent(g, "reflect", "TypeOf")
	fgsEventType := common.FgsApiIdent(g, "EventType")

	enumIndex := -1
	for i, enum := range f.Enums {
		if enum.GoIdent.GoName == "EventType" {
			enumIndex = i
		}
	}
	if enumIndex == -1 {
		return fmt.Errorf("Enum EventType not found")
	}
	enum := f.Enums[enumIndex]

	g.P(`func OpCodeForEventType(eventType ` + fgsEventType + `) (` + reflectType + `, error) {
        var opCode ` + reflectType + `
        switch eventType {`)

	for _, value := range enum.Values {
		valueIdent := g.QualifiedGoIdent(value.GoIdent)
		// skip over the UNDEF variant
		if valueIdent == "fgs.EventType_UNDEF" {
			continue
		}
		g.P(`case ` + valueIdent + `:
                opCode = ` + reflectTypeOf + `(&` + eventTypeToResponse(g, value) + `{})`)
	}

	g.P(` default:
            return nil, ` + common.FmtErrorf(g, "Unknown EventType %s", "eventType") + `
        }
        return opCode, nil
    }`)

	return nil
}

func eventTypeToResponse(g *protogen.GeneratedFile, eventType *protogen.EnumValue) string {
	suffix := strings.TrimPrefix(eventType.GoIdent.GoName, "EventType_")
	suffix = strcase.ToCamel(strings.ToLower(suffix))
	// Tls is a special case since it has no Process prefix
	if suffix == "ProcessTls" {
		suffix = "Tls"
	}
	// SockStats is a special case since it differs from PROCESS_SOCKSTATS
	if suffix == "ProcessSockstats" {
		suffix = "ProcessSockStats"
	}
	return common.FgsApiIdent(g, fmt.Sprintf("GetEventsResponse_%s", suffix))
}

// Generate generates boilerplate code for the filters
func Generate(gen *protogen.Plugin, f *protogen.File) error {
	g := common.NewGeneratedFile(gen, f, "filters")

	if err := generateOpCodeForEventType(g, f); err != nil {
		return err
	}

	return nil
}
