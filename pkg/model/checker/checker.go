// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package checker

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/decls"
	"cel.dev/cel-go/common/types"

	"cel.dev/cel-go/ext"
	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

type ApplicationCheckerResult interface {
	Ok() bool
	Failed() []string
}

// ResultPass represents a passing checker result.
type ResultPass struct{}

func (r *ResultPass) Ok() bool {
	return true
}

func (r *ResultPass) Failed() []string {
	return []string{}
}

// ResultFail represents a failing checker result.
type ResultFail struct {
	failed []string
}

func (r *ResultFail) Ok() bool {
	return false
}

func (r *ResultFail) Failed() []string {
	return r.failed
}

// Expression represents a single CEL expression along with a description
// of the expression. "tetra pstree check" command unmarshals the YAML file
// specified by the --yaml flag into a slice of Expression structs.
type Expression struct {
	Description string `yaml:"description"`
	Expression  string `yaml:"expression"`
}

func compile(env *cel.Env, expr string) (*cel.Ast, error) {
	ast, iss := env.Compile(expr)
	if iss.Err() != nil {
		return nil, iss.Err()
	}

	// Type-check the expression for correctness.
	checked, iss := env.Check(ast)
	// Report semantic errors, if present.
	if iss.Err() != nil {
		return nil, iss.Err()
	}

	if checked.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("wanted return type %q, got %q", cel.BoolType, checked.OutputType())
	}

	return ast, nil
}

func exportConsts(mapping map[string]int32) (declarations []*decls.VariableDecl) {
	for name, id := range mapping {
		declarations = append(declarations, decls.NewConstant(name, types.IntType, types.Int(int64(id))))
	}
	return declarations
}

// ApplicationModelChecker checks an application model using CEL expressions.
type ApplicationModelChecker struct {
	env *cel.Env
}

func NewApplicationModelChecker() (*ApplicationModelChecker, error) {
	applicationModelEventName := string((&appModelV1.ApplicationModelEvent{}).ProtoReflect().Descriptor().FullName())
	applicationModelName := string((&appModelV1.ApplicationModel{}).ProtoReflect().Descriptor().FullName())
	options := []cel.EnvOption{
		cel.Container("application_model.v1alpha"),
		cel.Variable("event", cel.ObjectType(applicationModelEventName)),
		cel.Variable("model", cel.ObjectType(applicationModelName)),
		cel.Variable("application_model", cel.ObjectType(applicationModelName)),
		cel.Variable("cluster_name", cel.StringType),
		cel.Variable("node_name", cel.StringType),
		cel.Variable("time", cel.TimestampType),
		cel.Types(
			&appModelV1.ApplicationModelEvent{},
			&appModelV1.ApplicationModel{},
			&appModelV1.ApplicationConnection{},
			&appModelV1.ApplicationProcessGroup{},
			&appModelV1.ApplicationHost{},
			&appModelV1.ApplicationNamespace{},
			&appModelV1.ApplicationWorkload{},
			&appModelV1.ApplicationContainer{},
		),
		ext.Network(),
		ext.Lists(),
		ext.Sets(),
	}

	options = append(options, cel.VariableDecls(exportConsts(v1alpha.WorkloadKind_value)...))

	// Convenience aliases for system calls.
	options = append(options, cel.VariableDecls(exportConsts(appModelV1.Sys_value)...))

	// Convenience aliases for ABIs.
	options = append(options, cel.VariableDecls(exportConsts(appModelV1.Abi_value)...))

	celEnv, err := cel.NewEnv(options...)
	if err != nil {
		return nil, err
	}

	return &ApplicationModelChecker{
		env: celEnv,
	}, nil
}

// CheckApplicationModelEvent checks an application model.
func (checker *ApplicationModelChecker) CheckApplicationModelEvent(ctx context.Context, appModelEvent *appModelV1.ApplicationModelEvent, exprs []string) (ApplicationCheckerResult, error) {
	failed := []string{}

	for _, expr := range exprs {
		ast, err := compile(checker.env, expr)
		if err != nil {
			return nil, fmt.Errorf("error compiling CEL expression: %w", err)
		}

		prg, err := checker.env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("error building CEL program: %w", err)
		}

		out, _, err := prg.ContextEval(ctx, map[string]any{
			// Top-level accessor for event
			"event": appModelEvent,
			// Convenience helpers for unwrapping event fields
			"cluster_name":      appModelEvent.ClusterName,
			"node_name":         appModelEvent.NodeName,
			"application_model": appModelEvent.ApplicationModel,
			"model":             appModelEvent.ApplicationModel, // Convenience alias for application_model
			"time":              appModelEvent.Time,
		})
		if err != nil {
			return nil, fmt.Errorf("error executing CEL program: %w", err)
		}

		v, err := out.ConvertToNative(reflect.TypeFor[bool]())
		if err != nil {
			return nil, fmt.Errorf("bad conversion of result to bool: %w", err)
		}

		res := v.(bool)
		if !res {
			failed = append(failed, expr)
		}
	}
	if len(failed) > 0 {
		return &ResultFail{
			failed,
		}, nil
	}
	return &ResultPass{}, nil
}

// CheckApplicationModelEventJSON checks an application model's JSON representation.
func (checker *ApplicationModelChecker) CheckApplicationModelEventJSON(ctx context.Context, appModelEventJSON string, exprs []string) (ApplicationCheckerResult, error) {
	appModel := &appModelV1.ApplicationModelEvent{}
	if err := protojson.Unmarshal([]byte(appModelEventJSON), appModel); err != nil {
		return nil, err
	}

	return checker.CheckApplicationModelEvent(ctx, appModel, exprs)
}

func indentString(s string) string {
	var indentedLines []string
	lines := strings.SplitSeq(strings.TrimSpace(s), "\n")
	for line := range lines {
		indentedLines = append(indentedLines, "   "+line)
	}
	return strings.Join(indentedLines, "\n")
}

func (checker *ApplicationModelChecker) CheckApplicationModelYAML(ctx context.Context, appModel *appModelV1.ApplicationModelEvent, celYAML string) (ApplicationCheckerResult, error) {
	fail := &ResultFail{}
	b, err := os.ReadFile(celYAML)
	if err != nil {
		return fail, err
	}
	var exprs []Expression
	err = yaml.Unmarshal(b, &exprs)
	if err != nil {
		return fail, err
	}
	for _, expr := range exprs {
		indentedExpr := indentString(expr.Expression)
		res, err := checker.CheckApplicationModelEvent(ctx, appModel, []string{expr.Expression})
		if err != nil {
			indentedError := indentString(err.Error())
			fmt.Printf("❌ %s\n%s\n%s\n", expr.Description, indentedError, indentedExpr)
			fail.failed = append(fail.failed, expr.Expression)
		} else if res.Ok() {
			fmt.Printf("✅ %s\n%s\n", expr.Description, indentedExpr)
		} else {
			fmt.Printf("❌ %s\n%s\n", expr.Description, indentedExpr)
			fail.failed = append(fail.failed, expr.Expression)
		}
	}
	if len(fail.failed) > 0 {
		return fail, nil
	}
	return &ResultPass{}, nil
}
