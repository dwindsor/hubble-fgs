package ipv4

import (
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/sensors/stats"
)

var (
	enableDns = false
)

func EnableDns() {
	enableDns = true
}

func MsgToIPv4Unix(m *api.MsgIPv4Event) *api.MsgIPv4EventUnix {
	unix := &api.MsgIPv4EventUnix{}

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
