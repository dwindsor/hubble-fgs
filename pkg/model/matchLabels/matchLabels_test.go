package matchLabels

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

func TestGetLabels(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	s1 := &LabelSet{
		Name:   "netpol",
		Labels: make(map[string]string),
		Policy: netpol,
	}

	s1.Labels["A"] = "a"
	s1.Labels["B"] = "b"
	s1.Labels["C"] = "c"
	s1.Labels["D"] = "d"
	s1.Labels["E"] = "e"

	s2 := s1.GetLabels()
	assert.Equal(t, s1.Labels, s2)
}

func TestSinglePolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s.Labels["A"] = "a"
	s.Labels["B"] = "b"
	s.Labels["C"] = "c"
	s.Labels["D"] = "d"
	s.Labels["E"] = "e"

	p.Add("s", s)
	match := p.Exists(s)
	assert.True(t, match, "keyset should exist")

	s2 := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s2.Labels["A"] = "a"
	s2.Labels["B"] = "b"
	s2.Labels["C"] = "c"
	s2.Labels["D"] = "d"
	s2.Labels["E"] = "e"
	s2.Labels["E"] = "f"
	match = p.Exists(s2)
	assert.False(t, match, "keyset should not match")

	s2.Labels["E"] = "e"
	s2.Labels["F"] = "f"
	match = p.Exists(s2)
	assert.True(t, match, "keyset should match even if extra keys exist")

	s3 := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s3.Labels["A"] = "a"
	s3.Labels["B"] = "b"
	s3.Labels["C"] = "c"
	s3.Labels["D"] = "d"
	match = p.Exists(s3)
	assert.False(t, match, "keyset with partial subset should fail")
	p.Flush()
}

func TestFlushPolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s.Labels["A"] = "a"
	s.Labels["B"] = "b"
	s.Labels["C"] = "c"
	s.Labels["D"] = "d"
	s.Labels["E"] = "e"

	p.Add("s", s)
	match := p.Exists(s)
	assert.True(t, match, "keyset should exist")

	p.Flush()
	match = p.Exists(s)
	assert.False(t, match, "keyset should not exist")
}

func TestDeletePolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s.Labels["A"] = "a"
	s.Labels["B"] = "b"
	s.Labels["C"] = "c"
	s.Labels["D"] = "d"
	s.Labels["E"] = "e"

	p.Add("s", s)
	match := p.Exists(s)
	assert.True(t, match, "keyset should exist")

	p.Remove("s")
	match = p.Exists(s)
	assert.False(t, match, "keyset should have been removed")
	p.Flush()
}

func TestManySimplePolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s := &LabelSet{
			Labels: make(map[string]string),
			Policy: netpol,
		}
		s.Labels[is] = is
		p.Add(is, s)
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s := &LabelSet{
			Labels: make(map[string]string),
			Policy: netpol,
		}
		s.Labels[is] = is
		match := p.Exists(s)
		assert.True(t, match, "keyset missing")
	}
	p.Flush()
}

func TestManyLongerPolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s := &LabelSet{
			Labels: make(map[string]string),
			Policy: netpol,
		}
		s.Labels[is] = is
		p.Add(is, s)
	}
	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s.Labels[is] = is
	}
	match := p.Exists(s)
	assert.True(t, match, "keyset missing")
	p.Flush()
}

func TestCollectionPolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s1 := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s2 := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}

	s1.Labels["A"] = "a"
	s1.Labels["B"] = "b"

	s2.Labels["B"] = "b"
	s2.Labels["C"] = "c"

	p.Add("s1", s1)
	p.Add("s2", s2)

	search := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	search.Labels["D"] = "D"
	// No overlap expect empty set
	collection := p.Collection(search)
	assert.Equal(t, 0, len(collection))
	delete(search.Labels, "D")
	// Find single entry
	search.Labels["A"] = "a"
	search.Labels["B"] = "b"
	collection = p.Collection(search)
	assert.Equal(t, 1, len(collection))
	// Find both s1 and s2
	search.Labels["C"] = "c"
	search.Labels["D"] = "d"
	collection = p.Collection(search)
	assert.Equal(t, 2, len(collection))
	// Find s1 set with valid keys but invalid values
	search.Labels["C"] = "C"
	collection = p.Collection(search)
	assert.Equal(t, 1, len(collection))
	// Find null set with valid keys but invalid values
	search.Labels["A"] = "A"
	collection = p.Collection(search)
	assert.Equal(t, 0, len(collection))
	p.Flush()
}

func TestPodAdd(t *testing.T) {
	name := "netpol"
	netpol := &types.TetragonNetworkPolicy{}
	p := PolicyList{}

	s := &LabelSet{
		Name:   name,
		Labels: make(map[string]string),
		Policy: netpol,
	}
	s.Labels["A"] = "a"
	s.Labels["B"] = "b"
	s.Labels["C"] = "c"
	s.Labels["D"] = "d"
	s.Labels["E"] = "e"

	p.Add(name, s)
	match := p.Exists(s)
	assert.True(t, match, "keyset should exist")

	epPod1 := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Kind:      "kindTest",
		Namespace: "workloadNamespace",
		Name:      "workloadTest1",
	}

	epPod2 := &endpoint.Endpoint{
		Type:      endpoint.PodType,
		Kind:      "kindTest",
		Namespace: "workloadNamespace",
		Name:      "workloadTest2",
	}

	err := p.AddPod(name, epPod1)
	assert.NoError(t, err)
	ls, ok := p[name]
	assert.True(t, ok)
	assert.Equal(t, ls.Name, name)
	assert.Equal(t, ls.Policy, netpol)
	assert.Equal(t, 1, len(ls.Endpoints))

	err = p.AddPod(name, epPod2)
	ls, ok = p[name]
	assert.True(t, ok)
	assert.NoError(t, err)
	assert.Equal(t, ls.Name, name)
	assert.Equal(t, ls.Policy, netpol)
	assert.Equal(t, 2, len(ls.Endpoints))

	p.Flush()
}

func BenchmarkMatchPolicy(b *testing.B) {
	netpol := &types.TetragonNetworkPolicy{}
	p := PolicyList{}

	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d%+200s", i, " ")
		s.Labels[is] = is
		p.Add(is, s)
	}

	find := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d%+100s", i, " ")
		find.Labels[is] = is
	}

	for i := 0; i < b.N; i++ {
		p.Exists(find)
	}
	p.Flush()
}

func BenchmarkCollection(b *testing.B) {
	netpol := &types.TetragonNetworkPolicy{}
	p := PolicyList{}

	s := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}

	for i := 0; i < 100; i++ {
		is := fmt.Sprintf("%d%+20s", i, " ")
		s.Labels[is] = is
		p.Add(is, s)
	}

	find := &LabelSet{
		Labels: make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 100; i++ {
		is := fmt.Sprintf("%d%+20s", i, " ")
		find.Labels[is] = is
	}

	var collection []*LabelSet
	for i := 0; i < b.N; i++ {
		collection = p.Collection(find)
	}
	assert.Equal(b, 100, len(collection))
	p.Flush()
}
