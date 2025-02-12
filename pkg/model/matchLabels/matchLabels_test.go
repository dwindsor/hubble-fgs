package matchLabels

import (
	"fmt"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/model/types"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	m.Run()
}

func TestSinglePolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s.Label["A"] = "a"
	s.Label["B"] = "b"
	s.Label["C"] = "c"
	s.Label["D"] = "d"
	s.Label["E"] = "e"

	p.Add("s", s)
	match := p.Exists(s)
	assert.True(t, match, "keyset should exist")

	s2 := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s2.Label["A"] = "a"
	s2.Label["B"] = "b"
	s2.Label["C"] = "c"
	s2.Label["D"] = "d"
	s2.Label["E"] = "e"
	s2.Label["E"] = "f"
	match = p.Exists(s2)
	assert.False(t, match, "keyset should not match")

	s2.Label["E"] = "e"
	s2.Label["F"] = "f"
	match = p.Exists(s2)
	assert.True(t, match, "keyset should match even if extra keys exist")

	s3 := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s3.Label["A"] = "a"
	s3.Label["B"] = "b"
	s3.Label["C"] = "c"
	s3.Label["D"] = "d"
	match = p.Exists(s3)
	assert.False(t, match, "keyset with partial subset should fail")
	p.Flush()
}

func TestFlushPolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s.Label["A"] = "a"
	s.Label["B"] = "b"
	s.Label["C"] = "c"
	s.Label["D"] = "d"
	s.Label["E"] = "e"

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
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s.Label["A"] = "a"
	s.Label["B"] = "b"
	s.Label["C"] = "c"
	s.Label["D"] = "d"
	s.Label["E"] = "e"

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
			Label:  make(map[string]string),
			Policy: netpol,
		}
		s.Label[is] = is
		p.Add(is, s)
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s := &LabelSet{
			Label:  make(map[string]string),
			Policy: netpol,
		}
		s.Label[is] = is
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
			Label:  make(map[string]string),
			Policy: netpol,
		}
		s.Label[is] = is
		p.Add(is, s)
	}
	s := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d", i)
		s.Label[is] = is
	}
	match := p.Exists(s)
	assert.True(t, match, "keyset missing")
	p.Flush()
}

func TestCollectionPolicy(t *testing.T) {
	netpol := &types.TetragonNetworkPolicy{}
	p := &PolicyList{}

	s1 := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	s2 := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}

	s1.Label["A"] = "a"
	s1.Label["B"] = "b"

	s2.Label["B"] = "b"
	s2.Label["C"] = "c"

	p.Add("s1", s1)
	p.Add("s2", s2)

	search := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	search.Label["D"] = "D"
	// No overlap expect empty set
	collection := p.Collection(search)
	assert.Equal(t, 0, len(collection))
	delete(search.Label, "D")
	// Find single entry
	search.Label["A"] = "a"
	search.Label["B"] = "b"
	collection = p.Collection(search)
	assert.Equal(t, 1, len(collection))
	// Find both s1 and s2
	search.Label["C"] = "c"
	search.Label["D"] = "d"
	collection = p.Collection(search)
	assert.Equal(t, 2, len(collection))
	// Find s1 set with valid keys but invalid values
	search.Label["C"] = "C"
	collection = p.Collection(search)
	assert.Equal(t, 1, len(collection))
	// Find null set with valid keys but invalid values
	search.Label["A"] = "A"
	collection = p.Collection(search)
	assert.Equal(t, 0, len(collection))
	p.Flush()
}

func BenchmarkMatchPolicy(b *testing.B) {
	netpol := &types.TetragonNetworkPolicy{}
	p := PolicyList{}

	s := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d%+200s", i, " ")
		s.Label[is] = is
		p.Add(is, s)
	}

	find := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 1000; i++ {
		is := fmt.Sprintf("%d%+100s", i, " ")
		find.Label[is] = is
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
		Label:  make(map[string]string),
		Policy: netpol,
	}

	for i := 0; i < 100; i++ {
		is := fmt.Sprintf("%d%+20s", i, " ")
		s.Label[is] = is
		p.Add(is, s)
	}

	find := &LabelSet{
		Label:  make(map[string]string),
		Policy: netpol,
	}
	for i := 0; i < 100; i++ {
		is := fmt.Sprintf("%d%+20s", i, " ")
		find.Label[is] = is
	}

	var collection []*LabelSet
	for i := 0; i < b.N; i++ {
		collection = p.Collection(find)
	}
	assert.Equal(b, 100, len(collection))
	p.Flush()
}
