package observer

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/covalentio/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
)

type argFilterTest struct {
	argTy       int
	argFilters  []v1alpha1.ArgFilter
	expectedRes []byte
}

func doArgFilterTest(t *testing.T, test *argFilterTest) {
	observer, _ := newDefaultObserver(t)
	res := observer.createArgFilter(test.argTy, test.argFilters)
	if bytes.Compare(test.expectedRes, res) != 0 {
		t.Fatalf("ArgFilterTest: %+v failed, res:%+v", test, res)
	}
}

func TestArgFilter(t *testing.T) {
	t.Run("2 int args",
		func(t *testing.T) {
			buildArr := func(xs ...uint32) []byte {
				ret := make([]byte, sizeofArgsFilter)
				for i, x := range xs {
					off := i * 4
					binary.LittleEndian.PutUint32(ret[off:], x)
				}
				return ret
			}

			expectedRes := buildArr(
				2,
				genericKprobeFilterEQ, 1,
				genericKprobeFilterEQ, 2,
			)
			t.Logf("L=%d", len(expectedRes))
			doArgFilterTest(t, &argFilterTest{
				argTy: GenericKprobeIntType,
				argFilters: []v1alpha1.ArgFilter{{
					Index: 0,
					Op:    "eq",
					Value: "1",
				}, {
					Index: 0,
					Op:    "eq",
					Value: "2",
				}},
				expectedRes: expectedRes,
			})
		},
	)
}
