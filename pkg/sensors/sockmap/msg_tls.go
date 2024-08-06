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
	"fmt"
	"io"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/yalue/native_endian"

	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/isovalent/hubble-fgs/pkg/grpc/tls"
	"github.com/isovalent/hubble-fgs/pkg/metrics/tlsmetrics"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
	readertls "github.com/isovalent/hubble-fgs/pkg/reader/tls"
	"github.com/isovalent/hubble-fgs/pkg/sensors/layer3/tcpCache"
)

var (
	// Do not use directly, should be accessed via getCache()
	__cache    *tlsCache
	tlsFilters []uint32
)

const (
	TLS_MIN_CERT_SIZE = 12
)

type MsgTLSEventCert struct {
	tls  *api.MsgTLSEvent
	cert []byte
}

type tlsCache = lru.Cache[networkapi.MsgSocketId, *MsgTLSEventCert]

// Return a reference to the tlsCache, allocating it first if necessary.
func getCache() (*tlsCache, error) {
	if __cache != nil {
		return __cache, nil
	}

	logger.GetLogger().WithField("size", enterpriseOption.Config.TlsCacheSize).Info("Initializing TLS cache")
	lru, err := lru.New[networkapi.MsgSocketId, *MsgTLSEventCert](enterpriseOption.Config.TlsCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS cache: %w", err)
	}

	__cache = lru
	return __cache, nil
}

func msgToTLSEventUnix(m *api.MsgTLSEvent, certs []string, errCode uint32, errState api.MsgTLSParserState) *tls.MsgTLSEventUnix {
	unix := &tls.MsgTLSEventUnix{}

	unix.Msg = m

	if errCode > 0 {
		unix.ServerCert.Error = errCode
		unix.ServerCert.ParserState = errState
	} else {
		unix.ServerCert.Certificates = certs
	}

	unix.Tuple = tcpCache.GetTuple(m.SocketCookie, m.SocketVersion)

	return unix
}

func HandleTLS(r *bytes.Reader) ([]observer.Event, error) {
	var errState api.MsgTLSParserState
	var certStrings []string
	var m *api.MsgTLSEvent
	errCode := uint32(0)

	cache, err := getCache()
	if err != nil {
		return nil, err
	}

	m = &api.MsgTLSEvent{}
	err = binary.Read(r, native_endian.NativeEndian(), m)
	if err != nil {
		return nil, err
	}

	/* Certificates will be part of continuation message we cache
	 * MsgTlsEvent until certificates arrive.
	 */
	if (m.ServerHello.Flags & api.TlsFlagCert) != 0 {
		tlsmetrics.TlsExpectedContinuationTotal().Inc()

		v := &MsgTLSEventCert{}
		v.tls = m
		v.cert = make([]byte, 0)
		socketId := networkapi.MsgSocketId{
			Cookie:  m.SocketCookie,
			Version: m.SocketVersion,
		}
		cache.Add(socketId, v)
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

	tlsmetrics.TlsActualContinuationTotal().Inc()

	cache, err := getCache()
	if err != nil {
		return nil, err
	}

	if err = binary.Read(r, native_endian.NativeEndian(), &op); err != nil {
		return nil, err
	}
	key := networkapi.MsgSocketId{}
	if err := binary.Read(r, native_endian.NativeEndian(), &key); err != nil {
		return nil, err
	}

	m, ok := cache.Get(key)
	/* If m is nil this implies either we incorrectly deleted a map
	 * entry. (datapath indicated no more bytes, but then sent more?)
	 * Or the entry was never populated in the first place. This would
	 * indicate a MSG_OP_TLS_CONT event without a matching MSG_OP_TLS
	 * event. */
	if m == nil || !ok {
		tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorSpuriousCerts, true).Inc()
		return nil, fmt.Errorf("missing original entry for continuation event")
	}

	if err := binary.Read(r, native_endian.NativeEndian(), &bytes); err != nil {
		tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorLengthRead, true).Inc()
		errCode = api.TlsCertificateErrorLengthRead
	} else if bytes == 0 {
		var errBpf uint32

		err := binary.Read(r, native_endian.NativeEndian(), &errBpf)
		if err == nil {
			errCode = uint32(errBpf)
			if errCode != 0 {
				err = binary.Read(r, native_endian.NativeEndian(), &errState)
				if err != nil {
					tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorMissingError, true).Inc()
					errCode = api.TlsCertificateErrorMissingError
				}
			}
		} else {
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorMissingError, true).Inc()
			errCode = api.TlsCertificateErrorMissingError
		}
	} else {
		m.cert = make([]byte, bytes)
		n, err := r.Read(m.cert)
		if err != nil && !errors.Is(err, io.EOF) {
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertRead, true).Inc()
			errCode = api.TlsCertificateErrorCertRead
		} else if n != int(bytes) {
			tlsmetrics.TlsErrorsTotal(api.TlsCertificateErrorCertRead, true).Inc()
			errCode = api.TlsCertificateErrorCertRead
		} else {
			certStrings, errCode = readertls.GetTLSCertificateString(m.cert)
		}
	}

	cache.Remove(key)
	ev := msgToTLSEventUnix(m.tls, certStrings, errCode, errState)
	return []observer.Event{ev}, nil
}
