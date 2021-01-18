package observer

import (
	"bytes"
	"encoding/binary"

	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/covalentio/hubble-fgs/pkg/reader"
)

func (k *ObserverKprobe) handleTls(r *bytes.Reader) {
	var m *api.MsgTLSEvent
	var certStrings []string
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
		k.tlsInProgress[m.Tuple] = v
		return
	}

	msgUnix := msgToTLSEventUnix(m, certStrings, errCode)
	/* OR filter together */
	k.observerListenersTLS(msgUnix)
	/* Keeping pretty printer because it helps debugging filters */
	if k.prettyPrinter {
		reader.ObserverTLSPrinter(msgUnix, k.log)
	}
}

func (k *ObserverKprobe) handleTlsCont(r *bytes.Reader) {
	var certStrings []string
	var errCode uint32
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

	m := k.tlsInProgress[key]
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
		var errBpf uint8

		errCode = api.TlsCertificateErrorLengthRead
		err := binary.Read(r, binary.LittleEndian, &errBpf)
		if err == nil {
			errCode = uint32(errBpf)
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
			k.tlsInProgress[key] = m
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
				k.tlsInProgress[key] = m
				return
			}

			certStrings, code = reader.GetTLSCertificateString(cert)
			if code != 0 {
				errCode = code
			}
		}
	}

	delete(k.tlsInProgress, key)
	msgUnix := msgToTLSEventUnix(m.tls, certStrings, errCode)

	/* OR filter together */
	k.observerListenersTLS(msgUnix)
	/* Keeping pretty printer because it helps debugging filters */
	if k.prettyPrinter {
		reader.ObserverTLSPrinter(msgUnix, k.log)
	}
}
