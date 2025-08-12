package filters

import (
	"testing"

	oss "github.com/cilium/tetragon/pkg/filters"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestParseFilterList(t *testing.T) {
	f := `{"event_set":["PROCESS_CONNECT", "PROCESS_LISTEN", "PROCESS_ACCEPT", "PROCESS_CLOSE"], "protocol": ["UDP"]}`
	filterProto, err := oss.ParseFilterList(f, true)
	assert.NoError(t, err)
	if diff := cmp.Diff(
		[]*tetragon.Filter{
			{EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_CONNECT, tetragon.EventType_PROCESS_LISTEN, tetragon.EventType_PROCESS_ACCEPT, tetragon.EventType_PROCESS_CLOSE}, Protocol: []tetragon.SocketProtocol{tetragon.SocketProtocol_UDP}},
		},
		filterProto,
		cmpopts.IgnoreUnexported(tetragon.Filter{}),
		cmpopts.IgnoreUnexported(tetragon.CapFilter{}),
		cmpopts.IgnoreUnexported(tetragon.CapFilterSet{}),
		cmpopts.IgnoreUnexported(wrapperspb.BoolValue{}),
	); diff != "" {
		t.Errorf("filter mismatch (-want +got):\n%s", diff)
	}
}
