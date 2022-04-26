package alignchecker

import (
	"reflect"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/api/processapi"
	"github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/exec/execvemap"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp"

	check "github.com/cilium/cilium/pkg/alignchecker"
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the datapath match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		// from perf_event_output
		"msg_ipv4_event": {reflect.TypeOf(api.MsgIPv4Event{})},
		"msg_exit":       {reflect.TypeOf(processapi.MsgExitEvent{})},
		"msg_creds":      {reflect.TypeOf(api.MsgCredEvent{})},
		"msg_test":       {reflect.TypeOf(api.MsgTestEvent{})},
		// "msg_kfree_skb":   {reflect.TypeOf(api.MsgKfreeSkb{})}, // api.MsgKfreeSkb(176) size does not match msg_kfree_skb(172)
		// "msg_tls_event":   {reflect.TypeOf(api.MsgTLSEvent{})}, // api.MsgTLSEvent(520) size does not match msg_tls_event(516)
		// "msg_generic_kprobe":	{reflect.TypeOf(api.MsgGenericKprobe{})}, // api.MsgGenericKprobe(56) size does not match msg_generic_kprobe(24184)
		// "msg_execve_event":	{reflect.TypeOf(api.MsgExecveEvent{})}, // api.MsgExecveEvent(112) size does not match msg_execve_event(1556)
		// "msg_http_event":	{reflect.TypeOf(api.MsgHttpEvent{})}, // api.MsgHttpEvent(1120) size does not match msg_http_event(1640)
		// "msg_tls_cont_event"
		// "msg_ipv4_tcp_connect"
		// "msg_ipv4_udp_event"
		// from maps
		"socketmap_value":  {reflect.TypeOf(tcp.SocketMapValue{})},
		"msg_tls_ipv4":     {reflect.TypeOf(tlsapi.MsgTLSIPv4{})},
		"execve_map_value": {reflect.TypeOf(execvemap.ExecveValue{})},
	}
	return check.CheckStructAlignments(path, toCheck)
}
