package record

import (
	"fmt"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/endpoint"
	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestDiffEmptySets(t *testing.T) {
	emptyA := []*DatapathRecord{}
	emptyB := []*DatapathRecord{}

	C := Diff(emptyA, emptyB)
	assert.Equal(t, 0, len(C))
}

func getRecordSlice() []*DatapathRecord {
	src := &types.ProcessTreeKey{
		CgroupId: uint64(1),
		Depth:    0,
		Self:     0,
	}

	epName1 := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Dns:       "",
		Kind:      "testKind",
		Namespace: "testNamespace",
		Name:      "testName1",
	}

	epName2 := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Dns:       "",
		Kind:      "testKind",
		Namespace: "testNamespace",
		Name:      "testName2",
	}

	epName3 := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Dns:       "",
		Kind:      "testKind",
		Namespace: "testNamespace",
		Name:      "testName3",
	}

	action := &DatapathAction{
		Quota: uint64(1),
		Reset: uint64(1),
		Deny:  uint64(1),
	}

	r1 := &DatapathRecord{
		Src:    src,
		EP:     epName1,
		Action: action,
		Init:   false,
	}
	r2 := &DatapathRecord{
		Src:    src,
		EP:     epName2,
		Action: action,
		Init:   false,
	}
	r3 := &DatapathRecord{
		Src:    src,
		EP:     epName3,
		Action: action,
		Init:   false,
	}

	return []*DatapathRecord{r1, r2, r3}
}

func TestDiffEmptyA(t *testing.T) {

	A := []*DatapathRecord{}
	B := getRecordSlice()
	C := Diff(A, B)
	assert.Equal(t, 0, len(C))
}

func TestDiffEmptyB(t *testing.T) {
	A := getRecordSlice()
	B := []*DatapathRecord{}
	C := Diff(A, B)
	assert.Equal(t, 3, len(C))
}

func TestRecordProperSubsets(t *testing.T) {
	A := getRecordSlice()
	B := []*DatapathRecord{A[0], A[1]}
	C := Diff(A, B)
	assert.Equal(t, 1, len(C))
	assert.Equal(t, C[0], A[2])

	B = []*DatapathRecord{A[0]}
	C = Diff(A, B)
	assert.Equal(t, 2, len(C))
	assert.Equal(t, C[0], A[1])
	assert.Equal(t, C[1], A[2])

	B = []*DatapathRecord{A[0], A[2]}
	C = Diff(A, B)
	assert.Equal(t, 1, len(C))
	assert.Equal(t, C[0], A[1])

	B = []*DatapathRecord{A[2]}
	C = Diff(A, B)
	assert.Equal(t, 2, len(C))
	assert.Equal(t, C[0], A[0])
	assert.Equal(t, C[1], A[1])

	B = []*DatapathRecord{}
	C = Diff(A, B)
	assert.Equal(t, 3, len(C))
	assert.Equal(t, C[0], A[0])
	assert.Equal(t, C[1], A[1])
	assert.Equal(t, C[2], A[2])
}

func TestRecordDisjoint(t *testing.T) {
	X := getRecordSlice()

	A := []*DatapathRecord{X[0], X[1]}
	B := []*DatapathRecord{X[0], X[2]}
	C := Diff(A, B)
	assert.Equal(t, 1, len(C))
	assert.Equal(t, C[0], X[1])

	A = []*DatapathRecord{X[1]}
	B = []*DatapathRecord{X[0], X[2]}
	C = Diff(A, B)
	assert.Equal(t, 1, len(C))
	assert.Equal(t, C[0], X[1])
}

// Benchmark worstcase time to Diff two sets of ~20000 Pods with 1000Pods per Namespace.
// Worstcase is all Pods found matching policy on delete giving Set(A) == Set(B)
func BenchmarkDiffRecord(b *testing.B) {
	src := &types.ProcessTreeKey{
		CgroupId: uint64(1),
		Depth:    0,
		Self:     0,
	}

	epName := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Dns:       "",
		Kind:      "testKind",
		Namespace: "testNamespace0",
		Name:      "..",
	}

	action := &DatapathAction{
		Quota: uint64(1),
		Reset: uint64(1),
		Deny:  uint64(1),
	}

	record := []*DatapathRecord{}

	for id := 0; id < 20000; id++ {
		s := *src
		s.CgroupId = uint64(id)

		ep := *epName
		ep.Name = fmt.Sprintf("testPod%d", id)

		a := *action

		if id%10000 == 0 {
			epName.Namespace = fmt.Sprintf("testNamespace%d", id)
		}

		r := &DatapathRecord{
			Src:    &s,
			EP:     &ep,
			Action: &a,
			Init:   false,
		}
		record = append(record, r)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Diff(record, record)
	}
}

// Benchmark case with small diff using two sets of ~20000 Pods with 1000Pods per Namespace.
// Worstcase is all Pods found matching policy on delete giving Set(A) == Set(B)
func BenchmarkOffByAFewDiffRecord(b *testing.B) {
	src := &types.ProcessTreeKey{
		CgroupId: uint64(1),
		Depth:    0,
		Self:     0,
	}

	epName := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Dns:       "",
		Kind:      "testKind",
		Namespace: "testNamespace0",
		Name:      "..",
	}

	action := &DatapathAction{
		Quota: uint64(1),
		Reset: uint64(1),
		Deny:  uint64(1),
	}

	record := []*DatapathRecord{}

	for id := 0; id < 20000; id++ {
		s := *src
		s.CgroupId = uint64(id)

		ep := *epName
		ep.Name = fmt.Sprintf("testPod%d", id)

		a := *action

		if id%10000 == 0 {
			epName.Namespace = fmt.Sprintf("testNamespace%d", id)
		}

		r := &DatapathRecord{
			Src:    &s,
			EP:     &ep,
			Action: &a,
			Init:   false,
		}
		record = append(record, r)
	}
	r1 := make([]*DatapathRecord, len(record))
	r2 := make([]*DatapathRecord, len(record)-1000)
	copy(r1, record)
	copy(r2, record)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Diff(r1, r2)
	}
}
