package network

import (
	"encoding/binary"
	"net"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/reader/ktime"
	api "github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func GetSocketStats(stats *api.MsgSocketStatsUnix) *tetragon.SocketStats {
	return &tetragon.SocketStats{
		BytesSubmitted:   stats.BytesSubmitted,
		BytesConsumed:    stats.BytesConsumed,
		BytesSent:        stats.BytesSent,
		BytesReceived:    stats.BytesReceived,
		SegsConsumed:     stats.ConsumedSegs,
		SegsIn:           stats.SegsIn,
		SegsSubmitted:    stats.SubmittedSegs,
		SegsOut:          stats.SegsOut,
		Srtt:             stats.SRtt,
		RetransmitsBytes: stats.RetransmitBytes,
		RetransmitsSegs:  stats.RetransmitSegs,
		ToZeroWindow:     stats.ToZeroWindow,
		SkDrop:           stats.SkDrop,
		SkbConsumeMisses: stats.SkbConsumeMisses,
	}
}

func MsgOpToProtocol(op uint8) tetragon.SocketProtocol {
	switch op {
	case ops.MSG_OP_TCPCONNECT,
		ops.MSG_OP_TCPCONNECTRET,
		ops.MSG_OP_TCPCLOSE,
		ops.MSG_OP_BIND,
		ops.MSG_OP_LISTEN,
		ops.MSG_OP_ACCEPT,
		ops.MSG_OP_TCPSTATS:
		return tetragon.SocketProtocol_TCP
	case ops.MSG_OP_UDPCONNECT,
		ops.MSG_OP_UDPCLOSE,
		ops.MSG_OP_UDPSTATS:
		return tetragon.SocketProtocol_UDP
	default:
		return tetragon.SocketProtocol_UNKNOWN
	}
}

func MsgToProtocol(event *api.MsgIPEventUnix) tetragon.SocketProtocol {
	return MsgOpToProtocol(event.Common.Op)
}

func GetIPv4(i uint32, op uint8) net.IP {
	if op == ops.MSG_OP_BIND {
		return net.IPv4zero
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func GetIP(i [2]uint64, op uint8, ipv6 bool) net.IP {
	if !ipv6 {
		return GetIPv4(uint32(i[0]), op)
	}
	if op == ops.MSG_OP_BIND {
		return net.IPv6zero
	}
	a := make([]byte, 8)
	b := make([]byte, 8)

	binary.LittleEndian.PutUint64(a, i[0])
	binary.LittleEndian.PutUint64(b, i[1])
	ip := append(a, b...)
	return ip
}

func GetSport(sport uint16) uint16 {
	return sport
}
func GetDport(dport uint16, op uint8) uint16 {
	if op == ops.MSG_OP_BIND || op == ops.MSG_OP_LISTEN {
		return 0
	}
	return SwapByte(dport)
}

func ObserverTCPPrinter(msg *api.MsgIPEventUnix, log logrus.FieldLogger) {
	e := syscall.Errno(uintptr(-msg.Return))
	/* In the event of an error time is {0} so will be obvious at printer time
	 * and its not clear what to do with this error so ignore it for now.
	 */
	eventTime, _ := ktime.DecodeKtime(int64(msg.Common.Ktime), true)

	op := msg.Common.Op

	log.WithFields(logrus.Fields{
		"op":               ops.OpCode(op).String(),
		"connect-ktime":    msg.Common.Ktime,
		"connect-walltime": eventTime,
		"proto":            msg.Tuple.Proto,
		"saddr":            GetIP(msg.Tuple.SAddr, op, msg.Tuple.IPv6 != 0).String(),
		"sport":            GetSport(msg.Tuple.SPort),
		"daddr":            GetIP(msg.Tuple.DAddr, op, msg.Tuple.IPv6 != 0).String(),
		"odaddr":           GetIPv4(msg.Tuple.GetPostDAddr(), op).String(),
		"dport":            GetDport(msg.Tuple.DPort, op),
		"odport":           GetDport(msg.Tuple.GetPostDPort(), op),
		"return":           unix.ErrnoName(e),
	}).Warn()
}

func SwapByte(b uint16) uint16 {
	return (b << 8) | (b >> 8)
}
