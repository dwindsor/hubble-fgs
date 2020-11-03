// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reader

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

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
	return s
}

func DecodeKtime(ktime int64) (time.Time, error) {
	clk := int32(unix.CLOCK_MONOTONIC)
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return time.Time{}, err
	}
	diff := ktime - currentTime.Nano()
	return time.Now().Add(time.Duration(diff)), nil
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

func ObserverIPV4TCPPrinter(msg *api.MsgIPv4TcpEventUnix, log logrus.FieldLogger) {
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

func GetTLSSession(session [64]uint8) string {
	var s []string
	size := session[32]
	if size > 31 {
		size = 31
	}
	if size == 0 {
		return ""
	}
	for _, h := range session[32+1 : size+32] {
		s = append(s, fmt.Sprintf("%02x", h))
	}
	return strings.Join(s, "")
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
	case 0x0403:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0203:
		return "TLS 1.1"
	case 0x0103:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("%x", version)
	}
}

func GetTLSSNI(sni [32]byte) (string, string) {
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

func GetTLSSupportedVersions(vers [16]byte, offset int) string {
	var s []string
	var length int

	if offset == 1 {
		length = int(vers[0])
		if length > 16 {
			length = 16
		}
	} else {
		// serverHello supported versions extensions only has the
		// single entry with the the negotiated version. And does
		// not have a length field.
		length = 2
	}
	for i := offset; i < length; i += 2 {
		t := binary.LittleEndian.Uint16(vers[i : i+2])

		switch t {
		case api.TLSVersion13:
			s = append(s, "TLS1.3")
		case api.TLSVersion12:
			s = append(s, "TLS1.2")
		case api.TLSVersion11:
			s = append(s, "TLS1.1")
		case api.TLSVersion10:
			s = append(s, "TLS1.0")
		case 0:
		default:
			s = append(s, "unknown("+strconv.FormatUint(uint64(t), 10)+")")
		}
	}
	return strings.Join(s, " ")
}

//func GetTLSRdns(rdns []byte) []string {
//	set := rdns[0]
//	setSize := rdns[1]
//
//	jj
//}

func GetTLSCertificateString(cert []byte) []string {
	var certificateString []string

	// Handshake Protocol Certificate: single byte offset because we
	// already accounted for Type, Version, and first byte of Length
	// by reading in 4B length that datapath used to cache total message
	// length.
	cIndex := 1
	// Certficate Length: Length of all the certificates
	certificatesLengthIndex := cIndex + 4
	// Point at first certificate, will advance as we parse each cert
	certificatesIndex := cIndex + 7

	cLength := make([]byte, 4)
	cLength[1] = cert[certificatesLengthIndex]
	cLength[2] = cert[certificatesLengthIndex+1]
	cLength[3] = cert[certificatesLengthIndex+2]
	length := binary.BigEndian.Uint32(cLength)

	for length > 0 {
		cLength[1] = cert[certificatesIndex]
		cLength[2] = cert[certificatesIndex+1]
		cLength[3] = cert[certificatesIndex+2]
		cIntLength := binary.BigEndian.Uint32(cLength)

		certificate := cert[certificatesIndex+3 : uint32(certificatesIndex)+3+cIntLength]
		parsedCert, err := x509.ParseCertificate(certificate)
		if err != nil {
			fmt.Printf("error %s\n", err)
			return certificateString
		}

		subjectRsdn := parsedCert.Subject.ToRDNSequence()
		certificateString = append(certificateString, subjectRsdn.String())

		length -= (cIntLength + 3)
		certificatesIndex += int(cIntLength) + 3
	}
	return certificateString
}

func ObserverTLSPrinter(msg *api.MsgTLSEventUnix, log logrus.FieldLogger) {
	op := msg.Common.Op
	typeSNI, nameSNI := GetTLSSNI(msg.ClientHello.SNI)

	log.WithFields(logrus.Fields{
		"op":                           api.OpCode(op).String(),
		"proto":                        msg.Tuple.Proto,
		"saddr":                        GetIP(msg.Tuple.SAddr, op).String(),
		"sport":                        GetSport(msg.Tuple.SPort),
		"dport":                        msg.Tuple.DPort,
		"daddr":                        GetIP(msg.Tuple.DAddr, op).String(),
		"Client-TLS-Version":           GetTLSVersion(msg.ClientHello.Version),
		"Server-TLS-Version":           GetTLSVersion(msg.ServerHello.Version),
		"SNI-Type":                     typeSNI,
		"SNI-Name":                     nameSNI,
		"Client-TLS-SupportedVersions": GetTLSSupportedVersions(msg.ClientHello.SupportedVersions, 1),
		"Server-TLS-SupportedVersions": GetTLSSupportedVersions(msg.ServerHello.SupportedVersions, 0),
		"cipher":                       GetTLSCipher(api.SwapByte(msg.ServerHello.Cipher)),
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
