package model

// Sorting implementations for repeated application model fields.

import (
	"cmp"
	"errors"
	"fmt"
	"slices"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var (
	ErrEmptyStack           = errors.New("empty stack")
	ErrUnhandledMessageType = errors.New("unhandled message type")
)

type stack[T any] struct {
	s []T
}

func (stack *stack[T]) push(v T) {
	stack.s = append(stack.s, v)
}

func (stack *stack[T]) pop() (v T, err error) {
	l := len(stack.s)
	if l == 0 {
		return v, ErrEmptyStack
	}
	v = stack.s[l-1]
	stack.s = stack.s[:l-1]
	return v, nil
}

func (stack *stack[T]) peek() (v T, err error) {
	l := len(stack.s)
	if l == 0 {
		return v, ErrEmptyStack
	}
	return stack.s[l-1], nil
}

func EnsureSorted(model *appModelV1.ApplicationModel) {
	toSort := stack[*[]protoreflect.Value]{}
	protorange.Options{}.Range(
		model.ProtoReflect(),
		// Push
		func(p protopath.Values) error {
			last := p.Index(-1)
			switch last.Step.Kind() {
			case protopath.FieldAccessStep:
				if last.Step.FieldDescriptor().IsList() {
					toSort.push(&[]protoreflect.Value{})
				}
			}
			return nil
		},
		// Pop
		func(p protopath.Values) error {
			last := p.Index(-1)
			switch last.Step.Kind() {
			case protopath.FieldAccessStep:
				if last.Step.FieldDescriptor().IsList() {
					ptr, err := toSort.pop()
					if err != nil {
						return fmt.Errorf("failed to pop sort buffer: %w", err)
					}
					if len(*ptr) == 0 {
						return nil
					}
					var unhandledErr error
					slices.SortStableFunc(*ptr, func(aVal, bVal protoreflect.Value) (res int) {
						b := bVal.Message().Interface()
						switch a := aVal.Message().Interface().(type) {
						case *appModelV1.ApplicationProcessGroup:
							b := b.(*appModelV1.ApplicationProcessGroup)
							res = cmp.Compare(a.Name, b.Name)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.Arguments, b.Arguments)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.Hash, b.Hash)
							if res != 0 {
								return res
							}
						case *appModelV1.ApplicationWorkload:
							b := b.(*appModelV1.ApplicationWorkload)
							res = cmp.Compare(a.Name, b.Name)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.Kind, b.Kind)
							if res != 0 {
								return res
							}
						case *appModelV1.ApplicationNamespace:
							b := b.(*appModelV1.ApplicationNamespace)
							res = cmp.Compare(a.Name, b.Name)
							if res != 0 {
								return res
							}
						case *appModelV1.ApplicationConnection:
							b := b.(*appModelV1.ApplicationConnection)
							res = cmp.Compare(a.DestinationName, b.DestinationName)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.DestinationPort, b.DestinationPort)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.BytesSent, b.BytesSent)
							if res != 0 {
								return res
							}
							res = cmp.Compare(a.BytesReceived, b.BytesReceived)
							if res != 0 {
								return res
							}
						default:
							unhandledErr = fmt.Errorf("%w: %T", ErrUnhandledMessageType, a)
							return 0
						}
						return 0
					})
					if unhandledErr != nil {
						return unhandledErr
					}
					for i := 0; i < last.Value.List().Len(); i++ {
						last.Value.List().Set(i, (*ptr)[i])
					}
				}
			case protopath.ListIndexStep:
				ptr, err := toSort.peek()
				if err != nil {
					return fmt.Errorf("failed to peek sort buffer: %w", err)
				}
				beforeLast := p.Index(-2)
				if beforeLast.Step.FieldDescriptor().Message() != nil {
					*ptr = append(*ptr, last.Value)
				}
			}
			return nil
		})
}
