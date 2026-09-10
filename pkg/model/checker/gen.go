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
	"fmt"
	"strings"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/isovalent/ipa/common/k8s/type/v1alpha"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	bytesReceivedPath = "tetragon.ApplicationConnection.bytes_received"
	bytesSentPath     = "tetragon.ApplicationConnection.bytes_sent"
)

const (
	timestampImport = "google.protobuf.Timestamp"
)

// stack implements a simple stack with Push, Pop, and PeekMut operations.
type stack[T any] []T

// Push pushes a new element onto the stack.
func (s *stack[T]) Push(elem T) {
	*s = append(*s, elem)
}

// Pop pops an element from the stack.
func (s *stack[T]) Pop() (T, error) {
	if len(*s) == 0 {
		var empty T
		return empty, fmt.Errorf("stack is empty")
	}

	elem := (*s)[len(*s)-1]
	*s = (*s)[:len(*s)-1]

	return elem, nil
}

// PeekMut returns a references to the top of the stack.
func (s *stack[T]) PeekMut() (*T, error) {
	if len(*s) == 0 {
		var empty T
		return &empty, fmt.Errorf("stack is empty")
	}

	return &(*s)[len(*s)-1], nil
}

// codegen contains holds code generation state.
type codegen struct {
	// Should we emit an `&&` on push?
	needsEmitAnd   bool
	doBreak        bool
	existsOneEmpty bool
	// How nested we are into exists_one() calls
	nestedListLevel int
	// A stack of pathnames.
	paths stack[stack[string]]
	out   strings.Builder
}

// newCodegen constructs a new codegen state.
func newCodegen() *codegen {
	return &codegen{
		needsEmitAnd:    false,
		doBreak:         false,
		existsOneEmpty:  false,
		nestedListLevel: 0,
		paths:           stack[stack[string]]{stack[string]{}},
		out:             strings.Builder{},
	}
}

// Output returns the generated code as a string.
func (gen *codegen) Output() string {
	return gen.out.String()
}

// formatPath formats the current path on the stack like `a.b.c`.
func (gen *codegen) formatPath() string {
	if len(gen.paths) == 0 {
		panic("base path should always exist")
	}
	return strings.Join(gen.paths[len(gen.paths)-1], ".")
}

// getVarName computes a unique variable name for use as the iteration variable
// in a call to `exists_one()`.
func (gen *codegen) getVarName() string {
	cnt := gen.nestedListLevel
	var vn strings.Builder
	for {
		vn.WriteRune(rune(cnt%'z' + 'a'))
		cnt -= 'z'
		if cnt < 'a' {
			break
		}
	}
	return vn.String()
}

// emitExistsOneStart emits a call to the `exists_one()` macro and manipulates
// pushes a new path onto the path stack so that we can access the iteration
// variable.
func (gen *codegen) emitExistsOneStart() {
	gen.nestedListLevel++
	gen.needsEmitAnd = false
	gen.existsOneEmpty = true
	varName := gen.getVarName()
	currPath := gen.formatPath()
	gen.paths.Push(stack[string]{varName})
	gen.out.WriteString(fmt.Sprintf("%s.exists(%s, ", currPath, varName))
}

// emitExistsOneEnd cleans up after emitExistsOneStart and emits the closing
// parenthesis to terminate the macro.
func (gen *codegen) emitExistsOneEnd() {
	gen.nestedListLevel--
	gen.needsEmitAnd = true
	// Handle empty structs in lists by simply returning true for them.
	if gen.existsOneEmpty {
		gen.out.WriteString("true")
	}
	gen.existsOneEmpty = false
	// Invariant: The base path should never get popped. In other words,
	// emitExistsOneEnd() should always have a coresponding
	// emitExistsOneStart().
	if (len(gen.paths)) == 1 {
		panic("refusing to pop base path")
	}
	gen.paths.Pop()
	gen.out.WriteString(")")
}

// maybeEmitAnd emits ` && ` if this is not the first expression in the AST or
// the first expression in an exists_one macro.
func (gen *codegen) maybeEmitAnd() {
	gen.existsOneEmpty = false
	if gen.needsEmitAnd {
		gen.out.WriteString(" && ")
	} else {
		gen.needsEmitAnd = true
	}
}

func shouldSkip(fd protoreflect.MessageDescriptor) bool {
	switch fd.FullName() {
	case timestampImport:
		return true
	default:
		return false
	}
}

// DoPush is called every time protorange visits a field. It performs the bulk
// of the code generation logic.
func (gen *codegen) DoPush(p protopath.Values) error {
	var fd protoreflect.FieldDescriptor
	last := p.Index(-1)

	if gen.doBreak {
		gen.doBreak = false
		return protorange.Break
	}

	path, err := gen.paths.PeekMut()
	if err != nil {
		return err
	}

	// Populate fd based on step
	switch last.Step.Kind() {
	case protopath.FieldAccessStep:
		fd = last.Step.FieldDescriptor()
	case protopath.ListIndexStep:
		gen.maybeEmitAnd()
		// It's a list element, so let's emit an `exists_one()` call here
		gen.emitExistsOneStart()
		return nil
	case protopath.MapIndexStep:
		panic("map support is TODO")
	default:
		return nil
	}

	// Skip bytes_sent and bytes_received
	switch fd.FullName() {
	case bytesReceivedPath:
		return nil
	case bytesSentPath:
		return nil
	}

	// Handle value
	switch v := last.Value.Interface().(type) {
	case protoreflect.Message:
		if shouldSkip(last.Value.Message().Descriptor()) {
			// Due to unfortunate behaviour with protorange.Break, we need to
			// flag for a break here and actually return a break in the first
			// child field of the message. Otherwise, the break sometimes
			// applies to the top-level message, which in this case terminates
			// the entire protorange early.
			gen.doBreak = true
		}
		path.Push(string(fd.Name()))
	case protoreflect.List:
		path.Push(string(fd.Name()))
	case protoreflect.Map:
		// No maps in ApplicationModel yet so let's worry about this when it becomes an issue.
		panic("map support is TODO")
	case protoreflect.EnumNumber:
		gen.maybeEmitAnd()
		path.Push(string(fd.Name()))
		gen.out.WriteString(fmt.Sprintf("%s == %s", gen.formatPath(), v1alpha.WorkloadKind_name[int32(v)]))
		path.Pop()
	case string, []byte:
		gen.maybeEmitAnd()
		path.Push(string(fd.Name()))
		// Strings need to be quoted, so let's do that.
		gen.out.WriteString(fmt.Sprintf("%s == %q", gen.formatPath(), v))
		path.Pop()
	case uint, uint8, uint16, uint32, uint64:
		gen.maybeEmitAnd()
		path.Push(string(fd.Name()))
		// Unsigned ints are special because CEL treats int literals as the int
		// type and does not support operations between int and uint without a
		// type cast. So perform the type cast here when we see one.
		gen.out.WriteString(fmt.Sprintf("%s == uint(%v)", gen.formatPath(), v))
		path.Pop()
	default:
		gen.maybeEmitAnd()
		path.Push(string(fd.Name()))
		gen.out.WriteString(fmt.Sprintf("%s == %v", gen.formatPath(), v))
		path.Pop()
	}

	return nil
}

// DoPop is called whenever protorange leaves a field. It performs some cleanup
// for the code generation logic.
func (gen *codegen) DoPop(p protopath.Values) error {
	last := p.Index(-1)

	switch last.Step.Kind() {
	case protopath.ListIndexStep:
		// End the exists_one() call
		gen.emitExistsOneEnd()
		return nil
	}

	path, err := gen.paths.PeekMut()
	if err != nil {
		return err
	}

	switch last.Value.Interface().(type) {
	case protoreflect.Message:
		// We're about to visit a new parent node, so pop the current one from the path.
		path.Pop()
	case protoreflect.List:
		// We're about to visit a new parent node, so pop the current one from the path.
		path.Pop()
	case protoreflect.Map:
		// No maps in ApplicationModel yet so let's worry about this when it becomes an issue.
		panic("map support is TODO")
	case protoreflect.EnumNumber:
		// Do nothing
	}

	return nil
}

// GenerateChecker generates a new ApplicationModelChecker based on an input ApplicationModelEvent.
func GenerateChecker(model *appModelV1.ApplicationModelEvent) (*ApplicationModelChecker, []string, error) {
	celSource, err := GenerateCheckerCEL(model)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating checker: %w", err)
	}

	checker, err := NewApplicationModelChecker()
	return checker, []string{celSource}, err
}

// GenerateCheckerCEL generates CEL checker source based on an input ApplicationModelEvent.
func GenerateCheckerCEL(model *appModelV1.ApplicationModelEvent) (string, error) {
	gen := newCodegen()

	// protorange.Options.Range visits every field in a depth-first traversal.
	// During traversal, it performs two callbacks: push and pop when visiting
	// and leaving a node respectively. We use both callbacks in the code generator.
	rft := model.ProtoReflect()

	err := protorange.Options{}.Range(
		rft,
		func(p protopath.Values) error {
			return gen.DoPush(p)
		},
		func(p protopath.Values) error {
			return gen.DoPop(p)
		},
	)
	if err != nil {
		return "", err
	}

	return gen.Output(), nil
}
