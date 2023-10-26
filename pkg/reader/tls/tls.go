package tls

import (
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/logger"
	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	"github.com/yalue/native_endian"
)

var (
	tlsVersion1_0 = "TLS1.0"
	tlsVersion1_1 = "TLS1.1"
	tlsVersion1_2 = "TLS1.2"
	tlsVersion1_3 = "TLS1.3"
)

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
		return tlsVersion1_3
	case api.TLSVersion12:
		return tlsVersion1_2
	case api.TLSVersion11:
		return tlsVersion1_1
	case api.TLSVersion10:
		return tlsVersion1_0
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
	vers, err := flv.Bytes()
	if err != nil {
		logger.GetLogger().WithError(err).Debug("TLS versions vector truncated")
	}

	// Dump FLV and bytes to logs when run with --log-level trace
	logger.GetLogger().WithField("flv", flv).WithField("bytes", vers).Trace("GetTLSSupportedVersions called")

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

// Version discovery for TLS <1.3 where negotiated version is not set.
func GetTLSNegotitatedVersion12(clientVersion, serverVersion string) string {
	// TLS version degrade to lowest common protocol support, so
	// walk through TLS versions starting at lowest and working
	// up checking if either client or server indicate the version.
	// If c or s have an unknown protocol we report that to ensure
	// we don't make an incorrect assumption.
	if strings.Contains(clientVersion, "unknown") {
		return clientVersion
	} else if strings.Contains(serverVersion, "unknown") {
		return serverVersion
	} else if clientVersion == tlsVersion1_0 || serverVersion == tlsVersion1_0 {
		return tlsVersion1_0
	} else if clientVersion == tlsVersion1_1 || serverVersion == tlsVersion1_1 {
		return tlsVersion1_1
	} else if clientVersion == tlsVersion1_2 || serverVersion == tlsVersion1_2 {
		return tlsVersion1_2
	}
	// We should never get here if we do lets use the
	// code below and we can count it in metrics because
	// it is unique from grpc layers unknown(#) syntax.
	return fmt.Sprintf("unknown(%s|%s)", clientVersion, serverVersion)
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
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorBadHeader, false).Inc()
			return nil, api.TlsCertificateErrorBadHeader
		}
		length := int(fragments[3])<<8 | int(fragments[4])
		fragments = fragments[5:]

		if len(fragments) < length {
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertPartial, false).Inc()
			return nil, api.TlsCertificateErrorCertPartial
		}

		handshake = append(handshake, fragments[:length]...)
		fragments = fragments[length:]
	}

	if len(fragments) > 0 {
		tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertPartial, false).Inc()
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
		tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertPartial, false).Inc()
		return nil, api.TlsCertificateErrorCertPartial
	}

	// Header: [ type 8b | length 24b | certs length 24b ]
	handshakeType := cert[0]
	if handshakeType != 11 {
		tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorBadHeader, false).Inc()
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
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertPartial, false).Inc()
			return certSubjects, api.TlsCertificateErrorCertPartial
		}

		certificate := cert[3 : 3+length]
		cert = cert[3+length:]

		parsedCert, err := x509.ParseCertificate(certificate)
		if err != nil {
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorParseX509, false).Inc()
			return certSubjects, api.TlsCertificateErrorParseX509
		}

		subjectRsdn := parsedCert.Subject.ToRDNSequence()
		certSubjects = append(certSubjects, subjectRsdn.String())
	}
	return certSubjects, 0
}
