// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package recorder

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"

	fieldmask_utils "github.com/mennanov/fieldmask-utils"

	"github.com/cilium/tetragon/pkg/logger"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	ecYaml "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker/yaml"
)

type Spec struct {
	// Metadata to use in the recorded eventchecker.
	Metadata ecYaml.Metadata `json:"metadata"`
	// Kind of eventchecker to record.
	CheckerKind string `json:"checkerKind"`
	// Fields to include and exclude in recorded event checkers. Keys are checker type
	// and values are lists of included and excluded field paths.
	FieldFilters map[string]CheckerFieldFilters `json:"fieldFilters,omitempty"`
	// Events to include and exclude while recording checkers, specified as lists of event
	// checkers.
	EventFilters EventFilters `json:"eventFilters"`
}

type EventFilters struct {
	// Events to include in recorded event checkers, specified as a list of event checkers.
	// Matches mean that the event will be included.
	Include []ecYaml.EventChecker `json:"include,omitempty"`
	// Events to excluded in recorded event checkers, specified as a list of event checkers.
	// Matches mean that the event will be excluded.
	Exclude []ecYaml.EventChecker `json:"exclude,omitempty"`
}

type CheckerFieldFilters struct {
	// Fields to include in the recorded checker, specified as a list of paths.
	Include []string `json:"include,omitempty"`
	// Fields to exclude in the recorded checker, specified as a list of paths.
	// Exclusions override inclusions.
	Exclude []string `json:"exclude,omitempty"`
}

// TODO: everything above this line will be moved in pkg/k8s eventually so we can generate
// CRDs with kubebuilder. I think this will need some work on the eventchecker side to add
// kubebuilder tags to everything (e.g. to get proper type validation on the kubebuilder
// side).

// FilterResult represents whether an event should be included or excluded. It is the
// return type of FilterResponse.
type FilterResult struct {
	slug string
}

// String implements the fmt.Stringer interface.
func (f *FilterResult) String() string {
	return f.slug
}

var (
	// Keep the event
	FilterResultKeep = FilterResult{slug: "keep"}
	// Discard the event
	FilterResultDiscard = FilterResult{slug: "discard"}
)

// FilterResponse filters a tetragon.GetEventsResponse using an EventFilters which is two
// distinct sets of ec.EventCheckers: one to include events and another to exclude.
// Exclusions will always take precedence over inclusions. In the absence of any inclusion
// filters, we assume that all events should be included by default.
func FilterResponse(filter *EventFilters, response *tetragon.GetEventsResponse) FilterResult {
	// Any match here means that we should exclude the event. Exclusion takes precedence
	// over inclusion.
	for _, checker := range filter.Exclude {
		if err := checker.CheckResponse(response); err == nil {
			return FilterResultDiscard
		}
	}

	// If we have no inclusion filters, set include to true by default.
	// Otherwise we only want to include in case an event matches an inclusion filter.
	include := len(filter.Include) == 0

	// Any match here means that we should include the event.
	for _, checker := range filter.Include {
		if err := checker.CheckResponse(response); err == nil {
			include = true
			break
		}
	}

	if include {
		return FilterResultKeep
	}

	return FilterResultDiscard
}

// fixupPathStringCase fixed up a path like `foo.bar.qux` into `Foo.Bar.Qux`.
func fixupPathStringCase(s string) string {
	var builder strings.Builder

	for i, r := range s {
		if i == 0 || s[i-1] == '.' {
			r = unicode.ToUpper(r)
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

// pathsToFieldFilter takes a list of period-separated field paths (e.g. a.b.c) and
// produces either and inclusion field mask or an exclusion field mask which can be used
// to filter ec.EventChecker fields. The first letter of a unit in a field path is not
// case sensitive, so it is not necessary to capitalize it. All other letters are case
// sensitive (i.e. no distinction between "foo" and "Foo" but "foobar" and "fooBar" are
// disinct cases).
func pathsToFieldFilter(paths []string, include bool) (fieldmask_utils.FieldFilter, error) {
	var mask fieldmask_utils.FieldFilter
	var err error

	if include {
		mask, err = fieldmask_utils.MaskFromPaths(paths, fixupPathStringCase)
	} else {
		mask, err = fieldmask_utils.MaskInverseFromPaths(paths, fixupPathStringCase)
	}

	// TODO: it might be nice to create and cache these masks at YAML parse time so that
	// we can avoid errors at runtime related to parsing the field paths.
	if err != nil {
		return nil, fmt.Errorf("failed to create mask from paths %v: %w", paths, err)
	}

	return mask, nil
}

// applyFieldFilter applies a field mask to an ec.EventChecker, producing a new
// ec.EventChecker with the filtered fields. This is the underlying implementation of
// FilterCheckerFields.
func applyFieldFilter(filter fieldmask_utils.FieldFilter, checker ec.EventChecker) (ec.EventChecker, error) {
	// Create a new instance of ec.EventChecker with the same underlying type
	newChecker := reflect.New(reflect.ValueOf(checker).Elem().Type()).Interface().(ec.EventChecker)
	// Apply the field filter to copy the old fields into the new ev.EventChecker
	if err := fieldmask_utils.StructToStruct(filter, checker, newChecker); err != nil {
		return nil, err
	}
	return newChecker, nil
}

// FilterCheckerFields applies field filters to an event checker checker, producing a new
// ec.EventChecker with the filtered fields.
func FilterCheckerFields(filter *CheckerFieldFilters, checker ec.EventChecker) (ec.EventChecker, error) {
	include, err := pathsToFieldFilter(filter.Include, true)
	if err != nil {
		return checker, fmt.Errorf("refusing to apply invalid include field filter: %w", err)
	}
	checker, err = applyFieldFilter(include, checker)
	if err != nil {
		return checker, fmt.Errorf("failed to apply include field filters: %w", err)
	}

	exclude, err := pathsToFieldFilter(filter.Exclude, false)
	if err != nil {
		return checker, fmt.Errorf("refusing to apply invalid exclude field filter: %w", err)
	}
	checker, err = applyFieldFilter(exclude, checker)
	if err != nil {
		return checker, fmt.Errorf("failed to apply exclude field filters: %w", err)
	}

	return checker, nil
}

type Recorder struct {
	*Spec
	checker ecYaml.EventCheckerConf
}

func NewRecorder(spec *Spec) *Recorder {
	var ordered bool
	switch strings.ToLower(spec.CheckerKind) {
	case "ordered":
		ordered = true
	case "unordered":
		ordered = false
	}
	return &Recorder{
		Spec: spec,
		checker: ecYaml.EventCheckerConf{
			APIVersion: "cilium.io/v1alpha1",
			Kind:       "EventChecker",
			Metadata:   spec.Metadata,
			Spec: ecYaml.MultiEventCheckerSpec{
				Ordered: ordered,
				Checks:  []ecYaml.EventChecker{},
			},
		},
	}
}

func (rec *Recorder) RecordResponse(res *tetragon.GetEventsResponse) error {
	if rec.Spec == nil {
		return fmt.Errorf("nil recorder spec")
	}

	if FilterResponse(&rec.EventFilters, res) == FilterResultDiscard {
		return nil
	}

	checker, err := ec.CheckerFromResponse(res)
	if err != nil {
		return fmt.Errorf("error creating checker from response: %w", err)
	}

	// *ec.ProcessExecChecker -> "exec"
	eventName := checkerToEventName(checker)
	if filter, ok := rec.FieldFilters[eventName]; ok {
		var err error
		checker, err = FilterCheckerFields(&filter, checker)
		if err != nil {
			return fmt.Errorf("error while filtering field: %w", err)
		}
	} else {
		logger.GetLogger().Debug("no field filters for event", "event", eventName)
	}

	// * is special and will apply to all events
	if filter, ok := rec.FieldFilters["*"]; ok {
		var err error
		checker, err = FilterCheckerFields(&filter, checker)
		if err != nil {
			return fmt.Errorf("error while filtering field: %w", err)
		}
	}

	rec.checker.Spec.Checks = append(rec.checker.Spec.Checks, ecYaml.EventChecker{
		EventChecker: checker,
	})

	return nil
}

func (rec *Recorder) Finish() *ecYaml.EventCheckerConf {
	return &rec.checker
}

func checkerToEventName(checker ec.EventChecker) string {
	type_ := fmt.Sprintf("%T", checker)
	parts := strings.Split(type_, ".")
	type_ = parts[len(parts)-1]
	type_ = strings.TrimLeft(type_, "*")
	type_ = strings.ToLower(type_)
	type_ = strings.TrimPrefix(type_, "process")
	type_ = strings.TrimSuffix(type_, "checker")
	return type_
}
