package model

// Sorting implementations for repeated application model fields.

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

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

// EnsureSorted recursively sorts all "repeated" fields of an [appModelV1.ApplicationModel].
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
							return CompareDestination(a.Destination, b.Destination)
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

// CompareDestination compares two [appModelV1.Destination].
func CompareDestination(a, b *appModelV1.Destination) int {
	res := cmp.Compare(fmt.Sprintf("%T", a.Type), fmt.Sprintf("%T", b.Type))
	if res != 0 {
		return res
	}
	// NB: It's impossible to have a.Type.(type) != b.Type.(Type) due to the check above
	switch at := a.Type.(type) {
	case *appModelV1.Destination_Dns:
		bt := b.Type.(*appModelV1.Destination_Dns)
		aNames := at.Dns.DestinationNames
		slices.Sort(aNames)
		bNames := bt.Dns.DestinationNames
		slices.Sort(bNames)
		res = cmp.Compare(strings.Join(aNames, ""), strings.Join(bNames, ""))
		if res != 0 {
			return res
		}
	case *appModelV1.Destination_Ip:
		bt := b.Type.(*appModelV1.Destination_Ip)
		ipA, errA := netip.ParseAddr(at.Ip.Ip)
		ipB, errB := netip.ParseAddr(bt.Ip.Ip)
		if errA != nil {
			if errB != nil {
				return 0
			}
			return -1
		}
		if errB != nil {
			return 1
		}
		res = ipA.Compare(ipB)
		if res != 0 {
			return res
		}
	case *appModelV1.Destination_Workload:
		bt := b.Type.(*appModelV1.Destination_Workload)
		res = cmp.Compare(at.Workload.Namespace, bt.Workload.Namespace)
		if res != 0 {
			return res
		}
		res = cmp.Compare(at.Workload.Name, bt.Workload.Name)
		if res != 0 {
			return res
		}
		res = cmp.Compare(at.Workload.Kind.String(), bt.Workload.Kind.String())
		if res != 0 {
			return res
		}
	default:
		panic(fmt.Sprintf("unexpected v1alpha.isDestination_Type: %#v", a.Type))
	}
	res = cmp.Compare(a.Port, b.Port)
	if res != 0 {
		return res
	}
	return 0
}

// CompareNetworkKeys compares two [NetworkKey].
func CompareNetworkKeys(a, b NetworkKey) int {
	if result := strings.Compare(a.SourceNamespace, b.SourceNamespace); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadKind.String(), b.SourceWorkloadKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceWorkloadName, b.SourceWorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceProcessName, b.SourceProcessName); result != 0 {
		return result
	}
	if result := strings.Compare(a.SourceProcessArgs, b.SourceProcessArgs); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationNames, b.DestinationNames); result != 0 {
		return result
	}
	ipA, errA := netip.ParseAddr(a.DestinationIP)
	ipB, errB := netip.ParseAddr(b.DestinationIP)
	if errA != nil && errB == nil {
		return -1
	}
	if errB != nil && errA == nil {
		return 1
	}
	if errA == nil && errB == nil {
		result := ipA.Compare(ipB)
		if result != 0 {
			return result
		}
	}
	if result := strings.Compare(a.DestinationWorkloadNamespace, b.DestinationWorkloadNamespace); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationWorkloadName, b.DestinationWorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.DestinationWorkloadKind.String(), b.DestinationWorkloadKind.String()); result != 0 {
		return result
	}
	if result := cmp.Compare(a.DestinationPort, b.DestinationPort); result != 0 {
		return result
	}
	return 0
}

// CompareProcessKeys compares two [ProcessKey].
func CompareProcessKeys(a, b ProcessKey) int {
	if result := strings.Compare(a.Namespace, b.Namespace); result != 0 {
		return result
	}
	if result := cmp.Compare(a.WorkloadKind.String(), b.WorkloadKind.String()); result != 0 {
		return result
	}
	if result := strings.Compare(a.WorkloadName, b.WorkloadName); result != 0 {
		return result
	}
	if result := strings.Compare(a.Name, b.Name); result != 0 {
		return result
	}
	return strings.Compare(a.Args, b.Args)
}
