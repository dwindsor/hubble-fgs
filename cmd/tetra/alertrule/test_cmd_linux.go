// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package alertrule

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/alerts"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
)

// NB: For now, this only works in linux due to some dependencies.
func testCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "test <yaml_file> <json_file>",
		Short: "test alert rule against a json file with tetragon events",
		Long:  "test alert rule against a json file with tetragon events\nPrints a json list of results: true or false if the alert matches and null if the parsing was unsuccessful",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {

			yamlb, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("failed to read yaml file %s: %w", args[0], err)
			}

			obj, err := alerts.FromYAML(string(yamlb))
			if err != nil {
				return err
			}
			ar, ok := obj.(*v1alpha1.AlertRule)
			if !ok {
				return fmt.Errorf("unexpected object type: %T", obj)
			}

			cef := filters.NewCELExpressionFilter(logger.GetLogger())
			celProgram, err := cef.CompileCEL(ar.Spec.Expression)
			if err != nil {
				return err
			}

			var file *os.File
			if args[1] == "-" {
				file = os.Stdin
			} else if file, err = os.Open(args[1]); err != nil {
				return err
			}

			scanner := bufio.NewScanner(file)
			unmarshaller := protojson.UnmarshalOptions{DiscardUnknown: true}

			matches := make([]*bool, 0)
			for scanner.Scan() {
				event := &tetragon.GetEventsResponse{}
				line := scanner.Bytes()
				err := unmarshaller.Unmarshal(line, event)
				if err != nil {
					return err
				}
				if event.String() == "" { // event is empty
					matches = append(matches, nil)
					continue
				}

				match, err := filters.EvalCEL(cmd.Context(), celProgram, event)
				if err != nil {
					return err
				}
				matches = append(matches, &match)
			}

			var jsonData []byte
			if len(matches) == 1 {
				jsonData, _ = json.Marshal(matches[0])
			} else {
				jsonData, _ = json.Marshal(matches)
			}
			fmt.Println(string(jsonData))

			return nil
		},
	}
}
