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
package observer

import (
	"bytes"
	"encoding/binary"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/reader"
)

var (
	/* Runtime Containers */
	tlsInProgress map[api.MsgTLSIPv4]*MsgTLSEventCert = make(map[api.MsgTLSIPv4]*MsgTLSEventCert)
)

func (k *ObserverKprobe) handleTls(r *bytes.Reader) {
	var errState api.MsgTLSParserState
	var certStrings []string
	var m *api.MsgTLSEvent
	errCode := uint32(0)

	m = &api.MsgTLSEvent{}
	err := binary.Read(r, binary.LittleEndian, m)
	if err != nil {
		return
	}

	/* Certificates will be part of continuation message we cache
	 * MsgTlsEvent until certificates arrive.
	 */
	if (m.ServerHello.Flags & api.TlsFlagCert) != 0 {
		v := &MsgTLSEventCert{}
		v.tls = m
		v.cert = make([]byte, 0)
		tlsInProgress[m.Tuple] = v
		return
	}

	msgUnix := msgToTLSEventUnix(m, certStrings, errCode, errState)
	/* OR filter together */
	k.observerListeners(msgUnix)
	/* Keeping pretty printer because it helps debugging filters */
	if k.prettyPrinter {
		reader.ObserverTLSPrinter(msgUnix, k.log)
	}
}

// bpf_skskb_post_cert and bpf_skskb_post_more_cert return additional
// information around their specific errors.
func errorHasState(errType uint32) bool {
	switch errType {
	case api.TlsCertificateErrorTooLarge,
		api.TlsCertificateErrorGetDataHdr,
		api.TlsCertificateErrorGetDataCert,
		api.TlsCertificateErrorGetDataMoreCert,
		api.TlsCertificateErrorCopyCert,
		api.TlsCertificateErrorCopyMoreCert:
		return true
	}
	return false
}

func (k *ObserverKprobe) handleTlsCont(r *bytes.Reader) {
	var certStrings []string
	var errCode uint32
	var errState api.MsgTLSParserState
	var bytes uint32
	var op uint8

	binary.Read(r, binary.LittleEndian, &op)
	key := api.MsgTLSIPv4{}
	err := binary.Read(r, binary.LittleEndian, &key)

	/* We hide a completion bit in the struct, but is not used to
	 * as part of the key lookup.
	 */
	remaining := key.Remaining
	key.Remaining = 0

	m := tlsInProgress[key]
	/* If m is nil this implies either we incorrectly deleted a map
	 * entry. (datapath indicated no more bytes, but then sent more?)
	 * Or the entry was never populated in the first place. This would
	 * indicate a MSG_OP_TLS_CONT event without a matching MSG_OP_TLS
	 * event. A small aside, apparently there is some small window
	 * where this could happen due to OOO events. To trigger this case
	 * one core would have to submit MSG_OP_TLS+MSG_OP_TLS_CONT event
	 * and then signal more data is needed. At this point in-theory an
	 * skb could be received on a different core and that cpu could
	 * post a MSG_OP_TLS_CONT event. But, really RSS should keep a
	 * TLS flow pinned to a core so somehow RSS would have to break
	 * first. TBD handle in-theory case with yet another cache?
	 */
	if m == nil {
		m = &MsgTLSEventCert{}
		m.tls = &api.MsgTLSEvent{}
		errCode = api.TlsCertificateErrorNullRead
	} else if err = binary.Read(r, binary.LittleEndian, &bytes); err != nil {
		errCode = api.TlsCertificateErrorLengthRead
	} else if bytes == 0 {
		var errBpf uint32

		errCode = api.TlsCertificateErrorLengthRead
		err := binary.Read(r, binary.LittleEndian, &errBpf)
		if err == nil {
			errCode = uint32(errBpf)
			if errorHasState(errCode) {
				binary.Read(r, binary.LittleEndian, &errState)
			}
		} else {
			errCode = api.TlsCertificateErrorMissingCode
		}
	} else {
		header := uint32(4)
		var code uint32

		/* If we are glueing together fragments we don't have a header */
		if len(m.cert) != 0 {
			header = 0
		}

		if m.header != 0 {
			header -= m.header
		}

		/* Its possible we don't even have the header to read */
		if bytes < header {
			m.cert = nil
			m.header = bytes + m.header
			tlsInProgress[key] = m
			return
		}
		m.header = 0

		cert := make([]byte, bytes-header)
		err = binary.Read(r, binary.LittleEndian, &cert)
		if err != nil {
			errCode = api.TlsCertificateErrorCertRead
		} else {
			if len(m.cert) != 0 {
				cert = append(m.cert, cert...)
			}
			if remaining != 0 || len(cert) < TLS_MIN_CERT_SIZE {
				/* Need to store and submit when remaining bits show up. */
				m.cert = cert
				m.header = 0
				tlsInProgress[key] = m
				return
			}

			certStrings, code = reader.GetTLSCertificateString(cert)
			if code != 0 {
				errCode = code
			}
		}
	}

	delete(tlsInProgress, key)
	msgUnix := msgToTLSEventUnix(m.tls, certStrings, errCode, errState)

	/* OR filter together */
	k.observerListeners(msgUnix)
	/* Keeping pretty printer because it helps debugging filters */
	if k.prettyPrinter {
		reader.ObserverTLSPrinter(msgUnix, k.log)
	}
}
