package ip

import (
	"bytes"
	"encoding/binary"

	"github.com/cilium/tetragon/pkg/observer"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/grpc/layer3"
	"github.com/isovalent/hubble-fgs/pkg/sensors/stats"
	"github.com/yalue/native_endian"
)

var (
	enableDns = false
)

func EnableDns() {
	enableDns = true
}

func MsgToIPUnix(m *api.MsgIPEvent) *layer3.MsgIPEventUnix {
	unix := &layer3.MsgIPEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.Return = m.Return
	unix.ProcessKey = m.ProcessKey
	unix.SockCookie = m.SockCookie
	unix.SocketStats = stats.MsgToSocketStatsUnix(&m.SocketStats)
	unix.SocketFlags = m.SocketFlags
	// no need to copy the pad here
	if enableDns {
		unix.SocketFlags |= api.SOCKFLAGS_TYPE_DNSREADY
	}
	return unix
}

func HandleIpError(r *bytes.Reader) ([]observer.Event, error) {
	m := api.MsgIPEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), &m)
	if err != nil {
		return nil, err
	}
	msgUnix := MsgToIPUnix(&m)
	return []observer.Event{msgUnix}, nil
}
