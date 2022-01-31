//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package reader

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/sirupsen/logrus"
	"github.com/yalue/native_endian"
	"golang.org/x/sys/unix"
)

func FromCString(cstr []byte) string {
	for i, c := range cstr {
		if c == 0 {
			return string(cstr[:i])
		}
	}
	return string(cstr)
}

func GetSocketStats(stats *api.MsgSocketStatsUnix) *fgs.SocketStats {
	return &fgs.SocketStats{
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
	}
}

func MsgOpToProtocol(op uint8) fgs.SocketProtocol {
	switch op {
	case api.MSG_OP_IPV4_TCPCONNECT,
		api.MSG_OP_IPV4_TCPCONNECTRET,
		api.MSG_OP_IPV4_TCPCLOSE,
		api.MSG_OP_IPV4_BIND,
		api.MSG_OP_IPV4_LISTEN,
		api.MSG_OP_IPV4_ACCEPT,
		api.MSG_OP_IPV4_TCPSTATS:
		return fgs.SocketProtocol_TCP
	case api.MSG_OP_IPV4_UDPCONNECT,
		api.MSG_OP_IPV4_UDPCLOSE,
		api.MSG_OP_IPV4_UDPSTATS:
		return fgs.SocketProtocol_UDP
	default:
		return fgs.SocketProtocol_UNKNOWN
	}
}

func MsgToProtocol(event *api.MsgIPv4EventUnix) fgs.SocketProtocol {
	return MsgOpToProtocol(event.Common.Op)
}

func GetIP(i uint32, op uint8) net.IP {
	if op == api.MSG_OP_IPV4_BIND {
		return net.IPv4zero
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, i)
	return ip
}

func DecodeCommonFlags(flags uint32) []string {
	var s []string
	if (flags & api.EventExecve) != 0 {
		s = append(s, "execve")
	}
	if (flags & api.EventExecveAt) != 0 {
		s = append(s, "execveat")
	}
	if (flags & api.EventProcFS) != 0 {
		s = append(s, "procFS")
	}
	if (flags & api.EventTruncFilename) != 0 {
		s = append(s, "truncFilename")
	}
	if (flags & api.EventTruncArgs) != 0 {
		s = append(s, "truncArgs")
	}
	if (flags & api.EventTaskWalk) != 0 {
		s = append(s, "taskWalk")
	}
	if (flags & api.EventMiss) != 0 {
		s = append(s, "miss")
	}
	if (flags & api.EventNeedsAUID) != 0 {
		s = append(s, "auid")
	}
	if (flags & api.EventErrorFilename) != 0 {
		s = append(s, "errorFilename")
	}
	if (flags & api.EventErrorArgs) != 0 {
		s = append(s, "errorArgs")
	}
	if (flags & api.EventNoCWDSupport) != 0 {
		s = append(s, "nocwd")
	}
	if (flags & api.EventRootCWD) != 0 {
		s = append(s, "rootcwd")
	}
	if (flags & api.EventErrorCWD) != 0 {
		s = append(s, "errorCWD")
	}
	if (flags & api.EventClone) != 0 {
		s = append(s, "clone")
	}
	if (flags & api.EventDockerNameErr) != 0 {
		s = append(s, "errorDockerNameCwd")
	}
	if (flags & api.EventDockerKnErr) != 0 {
		s = append(s, "errorDockerKn")
	}
	if (flags & api.EventDockerSubsysCgrpErr) != 0 {
		s = append(s, "errorDockerSubsysCgrp")
	}
	if (flags & api.EventDockerSubsysErr) != 0 {
		s = append(s, "errorDockerSubsys")
	}
	if (flags & api.EventDockerCgroupsErr) != 0 {
		s = append(s, "errorDockerCgroups")
	}

	return s
}

func DiffKtime(start, end uint64) time.Duration {
	return time.Duration(int64(end - start))
}

func NanoTimeSince(ktime int64) (time.Duration, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, err
	}
	diff := currentTime.Nano() - ktime
	return time.Duration(diff), nil
}
func DecodeKtime(ktime int64) (time.Time, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return time.Time{}, err
	}
	diff := ktime - currentTime.Nano()
	t := time.Now().Add(time.Duration(diff))
	return t.Truncate(1 * time.Millisecond), nil
}

func argsDecoderTrim(r rune) bool {
	if r == 0x00 {
		return true
	}
	return false
}

func SwapPath(path string) string {
	dirs := strings.Split(path, "/")
	for i := len(dirs)/2 - 1; i >= 0; i-- {
		opp := len(dirs) - 1 - i
		dirs[i], dirs[opp] = dirs[opp], dirs[i]
	}
	return strings.Join(dirs, "/")
}

func ArgsDecoder(s string, flags uint32) (string, string) {
	var b []byte
	var cwd string
	var hasCWD int
	args := ""

	b = append(b, 0x00)
	argTokens := bytes.Split(bytes.TrimRightFunc([]byte(s), argsDecoderTrim), b)
	flagsOR := ((flags & api.EventNoCWDSupport) |
		(flags & api.EventErrorCWD) |
		(flags & api.EventRootCWD))
	if flagsOR == 0 {
		hasCWD = 1
	} else {
		hasCWD = 0
	}

	if (flags & api.EventNoCWDSupport) != 0 {
		cwd = ""
	} else if (flags & api.EventErrorCWD) != 0 {
		cwd = ""
	} else if (flags & api.EventRootCWD) != 0 {
		cwd = "/"
	} else if (flags & api.EventProcFS) != 0 {
		cwd = strings.TrimSpace(string(argTokens[len(argTokens)-1]))
	} else {
		cwd = "/" + SwapPath(string(argTokens[len(argTokens)-1]))
	}

	if len(argTokens) > hasCWD {
		for i, a := range argTokens {
			if i == len(argTokens)-hasCWD {
				continue
			}
			if strings.Contains(string(a), " ") {
				args = args + " \"" + string(a) + "\""
			} else {
				if args == "" {
					args = string(a)
				} else {
					args = args + " " + string(a)
				}
			}
		}
	}
	return args, cwd
}

func GetSport(sport uint16) uint16 {
	return sport
}
func GetDport(dport uint16, op uint8) uint16 {
	if op == api.MSG_OP_IPV4_BIND || op == api.MSG_OP_IPV4_LISTEN {
		return 0
	}
	return api.SwapByte(dport)
}

func ObserverIPV4TCPPrinter(msg *api.MsgIPv4EventUnix, log logrus.FieldLogger) {
	e := syscall.Errno(uintptr(-msg.Return))
	/* In the event of an error time is {0} so will be obvious at printer time
	 * and its not clear what to do with this error so ignore it for now.
	 */
	eventTime, _ := DecodeKtime(int64(msg.Common.Ktime))

	op := msg.Common.Op

	log.WithFields(logrus.Fields{
		"op":               api.OpCode(op).String(),
		"connect-ktime":    msg.Common.Ktime,
		"connect-walltime": eventTime,
		"proto":            msg.Tuple.Proto,
		"saddr":            GetIP(msg.Tuple.SAddr, op).String(),
		"sport":            GetSport(msg.Tuple.SPort),
		"daddr":            GetIP(msg.Tuple.DAddr, op).String(),
		"odaddr":           GetIP(msg.Tuple.GetPostDAddr(), op).String(),
		"dport":            GetDport(msg.Tuple.DPort, op),
		"odport":           GetDport(msg.Tuple.GetPostDPort(), op),
		"return":           unix.ErrnoName(e),
	}).Warn()
}

func GetTLSSession(flv *api.FLV64) (s string) {
	session, _ := flv.Bytes()
	//       ^ TODO handle truncation?
	return hex.EncodeToString(session)
}

func GetTLSAlertLevel(level uint8) string {
	switch level {
	case 0x00:
		return ""
	case 0x01:
		return "warning"
	case 0x02:
		return "fatal"
	default:
		return fmt.Sprintf("0x%x", level)
	}
}

func GetTLSAlertDescription(description uint8) string {
	switch description {
	case 0x0:
		return ""
	case 0x28:
		return "handshake_failure"
	default:
		return fmt.Sprintf("0x%x", description)
	}
}

func GetTLSAlert(level uint8, description uint8) string {
	var s []string

	if level == 0 {
		return ""
	}
	s = append(s, GetTLSAlertLevel(level))
	s = append(s, GetTLSAlertDescription(description))
	return strings.Join(s, " ")
}

func GetTLSFlags(flags uint32) string {
	var s []string

	if (flags & api.TlsFlagCopyError) != 0 {
		s = append(s, "CopyError")
	}
	if (flags & api.TlsFlagMaxTlvs) != 0 {
		s = append(s, "MaxTLVError")
	}
	if (flags & api.TlsFlagFrameTooLarge) != 0 {
		s = append(s, "FrameTooLarge")
	}
	if (flags & api.TlsFlagHelloMsgMiss) != 0 {
		s = append(s, "HelloMsgMiss")
	}
	if (flags & api.TlsFlagHandshakeMsgMiss) != 0 {
		s = append(s, "HandshakeMsgMiss")
	}
	if (flags & api.TlsFlagCipherError) != 0 {
		s = append(s, "CipherError")
	}
	if (flags & api.TlsFlagCipherTooLarge) != 0 {
		s = append(s, "CipherTooLarge")
	}
	if (flags & api.TlsFlagCompressionError) != 0 {
		s = append(s, "CompressionError")
	}
	if (flags & api.TlsFlagCompressionTooLarge) != 0 {
		s = append(s, "CompressionTooLarge")
	}
	if (flags & api.TlsFlagExtError) != 0 {
		s = append(s, "ExtError")
	}
	if (flags & api.TlsFlagExtError) != 0 {
		s = append(s, "ExtError")
	}
	if (flags & api.TlsFlagExtTooLarge) != 0 {
		s = append(s, "ExtTooLarge")
	}
	if (flags & api.TlsFlagVersion) != 0 {
		s = append(s, "ExtVersion")
	}
	return strings.Join(s, " ")
}

func GetTLSVersion(version uint16) string {
	switch version {
	case api.TLSVersion13:
		return "TLS1.3"
	case api.TLSVersion12:
		return "TLS1.2"
	case api.TLSVersion11:
		return "TLS1.1"
	case api.TLSVersion10:
		return "TLS1.0"
	case api.TLSNone:
		return ""
	default:
		return "unknown(" + strconv.FormatUint(uint64(version), 10) + ")"
	}
}

func GetTLSSNI(sni [api.SNI_BUFFER_SIZE]byte) (string, string) {
	typeSNI := "unknown"
	switch sni[2] {
	case 0:
		typeSNI = "host_name"
	}
	nameLength := binary.BigEndian.Uint16(sni[3:5])
	if nameLength > api.SNI_BUFFER_SIZE-5 {
		nameLength = api.SNI_BUFFER_SIZE - 5
	}
	return typeSNI, string(sni[5 : 5+nameLength])
}

func GetTLSSupportedVersions(flv *api.FLV16, hasLength bool) string {
	var s []string
	vers, _ := flv.Bytes()
	//    ^ TODO handle truncated versions?

	if len(vers) < 2 {
		return ""
	} else if hasLength {
		end := int(vers[0]) + 1
		if end > len(vers) {
			end = len(vers)
		}
		vers = vers[1:end]
	} else {
		// serverHello supported versions extensions only has the
		// single entry with the the negotiated version. And does
		// not have a length field.
		vers = vers[0:2]
	}

	for i := 0; i <= len(vers)-2; i += 2 {
		t := native_endian.NativeEndian().Uint16(vers[i : i+2])
		s = append(s, GetTLSVersion(t))
	}
	return strings.Join(s, " ")
}

//func GetTLSRdns(rdns []byte) []string {
//	set := rdns[0]
//	setSize := rdns[1]
//
//	jj
//}

func defragHandshake(fragments []byte) ([]byte, uint32) {
	handshake := make([]byte, 0, len(fragments))

	for len(fragments) >= 5 {
		// TLS record header: [ type 8b | version 16b | length 16b ]
		typ := fragments[0]
		if typ != 22 {
			return nil, api.TlsCertificateErrorBadHeader
		}
		length := int(fragments[3])<<8 | int(fragments[4])
		fragments = fragments[5:]

		if len(fragments) < length {
			return nil, api.TlsCertificateErrorCertPartial
		}

		handshake = append(handshake, fragments[:length]...)
		fragments = fragments[length:]
	}

	if len(fragments) > 0 {
		return nil, api.TlsCertificateErrorCertPartial
	}

	return handshake, 0
}

func GetTLSCertificateString(fragments []byte) ([]string, uint32) {
	cert, code := defragHandshake(fragments)
	if code != 0 {
		return nil, code
	}
	if len(cert) < 6 {
		return nil, api.TlsCertificateErrorCertPartial
	}

	// Header: [ type 8b | length 24b | certs length 24b ]
	handshakeType := cert[0]
	if handshakeType != 11 {
		return nil, api.TlsCertificateErrorBadHeader
	}
	// Jump type + handshake length and parse the certificates length.
	cert = cert[4:]

	// Length of all certificates
	length := int(cert[0])<<16 | int(cert[1])<<8 | int(cert[2])
	cert = cert[3 : 3+length]

	var certSubjects []string

	for len(cert) > 3 {
		length = int(cert[0])<<16 | int(cert[1])<<8 | int(cert[2])

		if len(cert) < length {
			return certSubjects, api.TlsCertificateErrorCertPartial
		}

		certificate := cert[3 : 3+length]
		cert = cert[3+length:]

		parsedCert, err := x509.ParseCertificate(certificate)
		if err != nil {
			return certSubjects, api.TlsCertificateErrorParseX509
		}

		subjectRsdn := parsedCert.Subject.ToRDNSequence()
		certSubjects = append(certSubjects, subjectRsdn.String())
	}
	return certSubjects, 0
}

func ObserverTLSPrinter(msg *api.MsgTLSEventUnix, log logrus.FieldLogger) {
	op := msg.Common.Op
	typeSNI, nameSNI := GetTLSSNI(msg.ClientHello.SNI.Value)

	log.WithFields(logrus.Fields{
		"op":                           api.OpCode(op).String(),
		"saddr":                        GetIP(msg.Tuple.SAddr, op).String(),
		"sport":                        GetSport(msg.Tuple.SPort),
		"dport":                        msg.Tuple.DPort,
		"daddr":                        GetIP(msg.Tuple.DAddr, op).String(),
		"Client-TLS-Version":           GetTLSVersion(msg.ClientHello.Version),
		"Server-TLS-Version":           GetTLSVersion(msg.ServerHello.Version),
		"SNI-Type":                     typeSNI,
		"SNI-Name":                     nameSNI,
		"Client-TLS-SupportedVersions": GetTLSSupportedVersions(&msg.ClientHello.SupportedVersions, true),
		"Server-TLS-SupportedVersions": GetTLSSupportedVersions(&msg.ServerHello.SupportedVersions, false),
		"cipher":                       GetTLSCiphers(&msg.ServerHello.Cipher),
	}).Warn()
}

func ObserverKfreeSkbPrinter(msg *api.MsgKfreeSkb, log logrus.FieldLogger) {
	op := msg.Common.Op
	log.WithFields(logrus.Fields{
		"op":        api.OpCode(op).String(),
		"ret":       msg.Calltrace.Ret,
		"calltrace": msg.Calltrace.Stack,
	}).Debug()
}

func KprobeAction(act uint64) fgs.KprobeAction {
	switch act {
	case api.ActionPost:
		return fgs.KprobeAction_KPROBE_ACTION_POST
	case api.ActionFollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_FOLLOWFD
	case api.ActionSigKill:
		return fgs.KprobeAction_KPROBE_ACTION_SIGKILL
	case api.ActionUnfollowFd:
		return fgs.KprobeAction_KPROBE_ACTION_UNFOLLOWFD
	default:
		return fgs.KprobeAction_KPROBE_ACTION_UNKNOWN
	}
}

var (
	HttpMultiMessage = uint32(0x1)
)

func HttpErrorFlags(flags uint32) []string {
	var s []string

	if (flags & IterErrorCodeRead) != 0 {
		s = append(s, "ChunkReadFailed")
	}
	if (flags & IterErrorCodeOverrun) != 0 {
		s = append(s, "ChunkTooLarge")
	}
	if (flags & HttpMultiMessage) != 0 {
		s = append(s, "MultiMessageEvent")
	}
	return s
}
