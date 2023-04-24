package network

import (
	"encoding/binary"
	"fmt"
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
	rttHist := &tetragon.Histogram{}

	if stats.Rtt.B99 > 0 ||
		stats.Rtt.B90 > 0 ||
		stats.Rtt.B75 > 0 ||
		stats.Rtt.B50 > 0 ||
		stats.Rtt.B25 > 0 ||
		stats.Rtt.B10 > 0 ||
		stats.Rtt.B01 > 0 ||
		stats.Rtt.B00 > 0 {
		bucket99 := &tetragon.HistogramBucket{
			Percentile: 99,
			Size:       1,
			Count:      stats.Rtt.B99,
		}
		bucket90 := &tetragon.HistogramBucket{
			Percentile: 90,
			Size:       9,
			Count:      stats.Rtt.B90,
		}
		bucket75 := &tetragon.HistogramBucket{
			Percentile: 75,
			Size:       15,
			Count:      stats.Rtt.B75,
		}
		bucket50 := &tetragon.HistogramBucket{
			Percentile: 50,
			Size:       25,
			Count:      stats.Rtt.B50,
		}
		bucket25 := &tetragon.HistogramBucket{
			Percentile: 25,
			Size:       25,
			Count:      stats.Rtt.B25,
		}
		bucket10 := &tetragon.HistogramBucket{
			Percentile: 10,
			Size:       15,
			Count:      stats.Rtt.B10,
		}
		bucket01 := &tetragon.HistogramBucket{
			Percentile: 1,
			Size:       9,
			Count:      stats.Rtt.B01,
		}
		bucket00 := &tetragon.HistogramBucket{
			Percentile: 0,
			Size:       1,
			Count:      stats.Rtt.B00,
		}

		rttHist.Buckets = []*tetragon.HistogramBucket{
			bucket00,
			bucket01,
			bucket10,
			bucket25,
			bucket50,
			bucket75,
			bucket90,
			bucket99,
		}
	}

	latencyHist := &tetragon.Histogram{}

	if stats.Latency.B99 > 0 ||
		stats.Latency.B90 > 0 ||
		stats.Latency.B75 > 0 ||
		stats.Latency.B50 > 0 ||
		stats.Latency.B25 > 0 ||
		stats.Latency.B10 > 0 ||
		stats.Latency.B01 > 0 ||
		stats.Latency.B00 > 0 {
		bucket99 := &tetragon.HistogramBucket{
			Percentile: 99,
			Size:       1,
			Count:      stats.Latency.B99,
		}
		bucket90 := &tetragon.HistogramBucket{
			Percentile: 90,
			Size:       9,
			Count:      stats.Latency.B90,
		}
		bucket75 := &tetragon.HistogramBucket{
			Percentile: 75,
			Size:       15,
			Count:      stats.Latency.B75,
		}
		bucket50 := &tetragon.HistogramBucket{
			Percentile: 50,
			Size:       25,
			Count:      stats.Latency.B50,
		}
		bucket25 := &tetragon.HistogramBucket{
			Percentile: 25,
			Size:       25,
			Count:      stats.Latency.B25,
		}
		bucket10 := &tetragon.HistogramBucket{
			Percentile: 10,
			Size:       15,
			Count:      stats.Latency.B10,
		}
		bucket01 := &tetragon.HistogramBucket{
			Percentile: 1,
			Size:       9,
			Count:      stats.Latency.B01,
		}
		bucket00 := &tetragon.HistogramBucket{
			Percentile: 0,
			Size:       1,
			Count:      stats.Latency.B00,
		}

		latencyHist.Buckets = []*tetragon.HistogramBucket{
			bucket00,
			bucket01,
			bucket10,
			bucket25,
			bucket50,
			bucket75,
			bucket90,
			bucket99,
		}
	}

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
		Rtt:              rttHist,
		Latency:          latencyHist,
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

// TupleAddrString returns two strings to represent the tuple addresses.
// The first is the source, and the second is the destination.
func TupleAddrString(tuple *api.MsgIPTuple, op uint8) (string, string) {
	var saddr, daddr net.IP
	var sport, dport uint16

	saddr = GetIP(tuple.SAddr, op, tuple.IPv6 == 1)
	daddr = GetIP(tuple.DAddr, op, tuple.IPv6 == 1)

	sport = GetSport(tuple.SPort)
	dport = GetDport(tuple.DPort, op)

	wrapAddr := func(ip net.IP) string {
		if tuple.IPv6 == 1 {
			return fmt.Sprintf("[%s]", ip)
		}
		return fmt.Sprint(ip)
	}

	return fmt.Sprintf("%s:%d", wrapAddr(saddr), sport), fmt.Sprintf("%s:%d", wrapAddr(daddr), dport)
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
