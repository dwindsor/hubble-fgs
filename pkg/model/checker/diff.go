//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package checker

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/breml/jsondiffprinter"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	fieldmask_utils "github.com/mennanov/fieldmask-utils"
	"github.com/wI2L/jsondiff"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/isovalent/hubble-fgs/pkg/model"
)

func getOptions(opts []Option) *options {
	oo := &options{}
	for _, opt := range opts {
		opt(oo)
	}
	return oo
}

type options struct {
	printColor    bool
	hideUnchanged bool
	ignores       []string
}

type Option func(*options)

// PrintColor instructs the pretty printer to print in color.
func PrintColor() Option {
	return func(opts *options) {
		opts.printColor = true
	}
}

// HideUnchanged instructs the pretty printer to hide any unchanged fields in the output.
func HideUnchanged() Option {
	return func(opts *options) {
		opts.hideUnchanged = true
	}
}

// IgnoreFields ignores the supplied list of fields when taking the JSON diff.
// Each field is a period-separated path with lower snake case field names.
func IgnoreFields(fields ...string) Option {
	return func(opts *options) {
		opts.ignores = append(opts.ignores, fields...)
	}
}

// Converts a string to camel case.
func fixupSnakeCaseString(s string, upper bool) string {
	var builder strings.Builder

	for i, r := range s {
		if s[i] == '_' {
			continue
		}
		if i == 0 && upper {
			r = unicode.ToUpper(r)
		}
		if i != 0 && s[i-1] == '_' {
			r = unicode.ToUpper(r)
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

// JsonDiff takes the diff between two application models and returns as a
// serialized JSON patch and a boolean indicating whether there were any changes.
func JsonDiff(a, b *appModelV1.ApplicationModel, opts ...Option) ([]byte, bool, error) {
	oo := getOptions(opts)
	return innerJsonDiff(a, b, oo)
}

func innerJsonDiff(a, b *appModelV1.ApplicationModel, oo *options) ([]byte, bool, error) {
	// Models need to be sorted here to enable proper comparison
	model.EnsureSorted(a)
	model.EnsureSorted(b)

	var dstA, dstB *appModelV1.ApplicationModel
	if len(oo.ignores) > 0 {
		dstA = &appModelV1.ApplicationModel{}
		dstB = &appModelV1.ApplicationModel{}

		filter, err := fieldmask_utils.MaskInverseFromPaths(oo.ignores, func(s string) string { return fixupSnakeCaseString(s, true) })
		if err != nil {
			return nil, false, fmt.Errorf("error creating field mask: %w", err)
		}

		err = fieldmask_utils.StructToStruct(filter, a, dstA)
		if err != nil {
			return nil, false, fmt.Errorf("error applying field mask to A: %w", err)
		}

		err = fieldmask_utils.StructToStruct(filter, b, dstB)
		if err != nil {
			return nil, false, fmt.Errorf("error applying field mask to B: %w", err)
		}
	} else {
		dstA = a
		dstB = b
	}

	// TODO: jsondiff.LCS() causes a bug with some sequences, but it makes the
	// output much nicer. Add it back in when we have a chance to get a fix in
	// place.
	patch, err := jsondiff.Compare(dstA, dstB, jsondiff.Rationalize())
	if err != nil {
		return nil, false, err
	}

	out, err := json.Marshal(patch)
	if err != nil {
		return nil, false, err
	}

	return out, len(patch) != 0, nil
}

// PrettyJsonDiff takes the diff between two application models and returns a
// pretty string representation of the diff. Returns the empty string if there
// are no changes.
func PrettyJsonDiff(a, b *appModelV1.ApplicationModel, opts ...Option) (string, error) {
	oo := getOptions(opts)
	patch, changed, err := innerJsonDiff(a, b, oo)
	if err != nil {
		return "", err
	}

	original, err := protojson.MarshalOptions{
		EmitUnpopulated:   true,
		EmitDefaultValues: true,
		UseProtoNames:     true,
	}.Marshal(a)
	if err != nil {
		return "", err
	}
	if !changed {
		return "", nil
	}

	var out strings.Builder
	diffOpts := []jsondiffprinter.Option{
		jsondiffprinter.WithWriter(&out),
		jsondiffprinter.WithColor(oo.printColor),
		jsondiffprinter.WithHideUnchanged(oo.hideUnchanged),
	}

	err = jsondiffprinter.Format(original, patch, diffOpts...)
	if err != nil {
		return "", err
	}

	return out.String(), nil
}
