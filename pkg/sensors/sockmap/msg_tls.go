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

package sockmap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/yalue/native_endian"
)

var (
	/* Runtime Containers */
	tlsInProgress map[api.MsgTLSIPv4]*MsgTLSEventCert = make(map[api.MsgTLSIPv4]*MsgTLSEventCert)
	tlsSelectors  [128]byte
)

const (
	TLS_MIN_CERT_SIZE = 12
)

type MsgTLSEventCert struct {
	tls  *api.MsgTLSEvent
	cert []byte
}

func msgToTLSEventUnix(m *api.MsgTLSEvent, certs []string, errCode uint32, errState api.MsgTLSParserState) *api.MsgTLSEventUnix {
	unix := &api.MsgTLSEventUnix{}

	unix.Common = m.Common
	unix.Tuple = m.Tuple
	unix.ClientHello = m.ClientHello
	unix.ServerHello = m.ServerHello
	unix.ProcessKey = m.ProcessKey

	if errCode > 0 {
		unix.ServerCert.Error = errCode
		unix.ServerCert.ParserState = errState
	} else {
		unix.ServerCert.Certificates = certs
	}
	return unix
}

func HandleTLS(r *bytes.Reader) ([]observer.Event, error) {
	var errState api.MsgTLSParserState
	var certStrings []string
	var m *api.MsgTLSEvent
	errCode := uint32(0)

	m = &api.MsgTLSEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), m)
	if err != nil {
		return nil, err
	}

	/* Certificates will be part of continuation message we cache
	 * MsgTlsEvent until certificates arrive.
	 */
	if (m.ServerHello.Flags & api.TlsFlagCert) != 0 {
		v := &MsgTLSEventCert{}
		v.tls = m
		v.cert = make([]byte, 0)
		tlsInProgress[m.Tuple] = v
		return nil, nil
	}

	return []observer.Event{msgToTLSEventUnix(m, certStrings, errCode, errState)}, nil
}

// HandleTLSCont handles a TLS continuation event that was split up by the
// kernel. It will merge them together and pass it up to the TLS Listener as a
// full event.
func HandleTLSCont(r *bytes.Reader) ([]observer.Event, error) {
	var certStrings []string
	var errCode uint32
	var errState api.MsgTLSParserState
	var bytes uint32
	var op uint8

	if err := binary.Read(r, native_endian.NativeEndian(), &op); err != nil {
		return nil, err
	}
	key := api.MsgTLSIPv4{}
	if err := binary.Read(r, native_endian.NativeEndian(), &key); err != nil {
		return nil, err
	}

	/* We hide a completion bit in the struct, but is not used to
	 * as part of the key lookup.
	 */
	key.Remaining = 0

	m := tlsInProgress[key]
	/* If m is nil this implies either we incorrectly deleted a map
	 * entry. (datapath indicated no more bytes, but then sent more?)
	 * Or the entry was never populated in the first place. This would
	 * indicate a MSG_OP_TLS_CONT event without a matching MSG_OP_TLS
	 * event. */
	if m == nil {
		m = &MsgTLSEventCert{}
		m.tls = &api.MsgTLSEvent{}
		errCode = api.TlsCertificateErrorSpuriousCerts
	} else {
		if err := binary.Read(r, native_endian.NativeEndian(), &bytes); err != nil {
			errCode = api.TlsCertificateErrorLengthRead
		} else if bytes == 0 {
			var errBpf uint32

			err := binary.Read(r, native_endian.NativeEndian(), &errBpf)
			if err == nil {
				errCode = uint32(errBpf)
				if errCode != 0 {
					err = binary.Read(r, native_endian.NativeEndian(), &errState)
					if err != nil {
						errCode = api.TlsCertificateErrorMissingError
					}
				}
			} else {
				errCode = api.TlsCertificateErrorMissingError
			}
		} else {
			m.cert = make([]byte, bytes)
			n, err := r.Read(m.cert)
			if err != nil && !errors.Is(err, io.EOF) {
				errCode = api.TlsCertificateErrorCertRead
			} else if n != int(bytes) {
				errCode = api.TlsCertificateErrorCertRead
			} else {
				certStrings, errCode = reader.GetTLSCertificateString(m.cert)
			}
		}
	}

	delete(tlsInProgress, key)
	return []observer.Event{msgToTLSEventUnix(m.tls, certStrings, errCode, errState)}, nil
}
