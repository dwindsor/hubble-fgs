package ip

import (
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/sensors/stats"
)

var (
	enableDns = false
)

func EnableDns() {
	enableDns = true
}

func MsgToIPUnix(m *api.MsgIPEvent) *api.MsgIPEventUnix {
	unix := &api.MsgIPEventUnix{}

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
