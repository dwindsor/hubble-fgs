//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package http

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/sirupsen/logrus"

	api "github.com/isovalent/hubble-fgs/pkg/api/httpapi"
	"github.com/isovalent/hubble-fgs/pkg/api/networkapi"
	"github.com/isovalent/hubble-fgs/pkg/api/ops"
	"github.com/isovalent/hubble-fgs/pkg/chunks"
	"github.com/isovalent/hubble-fgs/pkg/grpc/httpproto"
	readerhttp "github.com/isovalent/hubble-fgs/pkg/reader/http"
	"github.com/isovalent/hubble-fgs/pkg/sensors/program/sk"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/tcp"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/yalue/native_endian"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	filters []uint32

	// Runtime aggregation of request/response
	aggregate          *lru.Cache[api.HttpKey, *httpproto.MsgHttpEventUnix]
	moreBytes          *lru.Cache[api.HttpKey, *httpproto.MsgHttpEventUnix]
	aggregateEnable    bool
	moreBytesEnable    bool
	cacheSize          = 1024
	moreBytesCacheSize = 32

	// The per-connection and per-direction HTTP/2 state that is required to decompress the
	// header frames.
	http2StateCache     *lru.Cache[networkapi.MsgIPTuple, *http2State]
	http2StateCacheSize = 16384

	// Number of frames we can queue. If a HTTP/2 frame with an event sequence number that is
	// beyond 'frameQueueSize' away from the next expected one is received the queue is reset
	// and frames are potentially lost. This may potentially confuse the header decoder and some future
	// frames may fail to decode.
	frameQueueSize = 128

	// Enable HTTP2 handling
	enableHttp2 = true
)

const (
	// 100MiB
	HTTP_CLAMP_URL_LENGTH = 100 * 1024 * 1024
)

var (
	HttpMoreHeadersNeeded = uint32(1)
)

func httpNeedsMoreBytes(flags uint32) bool {
	return HttpMoreHeadersNeeded&flags > 0
}

var (
	Skmsg = program.Builder(
		"bpf_http.o",
		"sk_msg",
		"sk_msg/fgs",
		"tg_sk_msg_fgs",
		"http_skmsg")

	SkSkbParser = program.Builder(
		"bpf_http_parser.o",
		"sk_skb",
		"sk_skb_http_parser/fgshttp",
		"tg_sk_skb_parser",
		"sk_skb_parser")

	SkSkbVerdict = program.Builder(
		"bpf_http_verdict.o",
		"sk_skb",
		"sk_skb/stream_verdict/fgshttp",
		"tg_skskb_http_verdict",
		"sk_skb_verdict")

	// Http maps
	HTTPContext  = tcp.HTTPContext
	TailCalls    = program.MapBuilder("http1_calls", Skmsg)
	SkbTailCalls = program.MapBuilder("http1_calls_skb", SkSkbVerdict)
	HttpErrorMap = program.MapBuilder("tg_http_err_stats", Skmsg)
	// Sockops filters
	HTTPFilterMap = sockops.HttpFilterMap
	// Socket links
	SocketMap   = tcp.SocketMap
	SocketStats = tcp.SocketStats
)

type httpSensor struct {
	name string
}

func (http *httpSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	err := sk.LoadSkProgram(args.BPFDir, args.MapDir, args.Load, sockops.HttpSockMap, args.Verbose)
	if err != nil {
		return err
	}

	if utils.SkSkbParserRequired() {
		err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbParser, sockops.HttpSockMap, args.Verbose)
		if err != nil {
			return err
		}
	}
	err = sk.LoadSkProgram(args.BPFDir, args.MapDir, SkSkbVerdict, sockops.HttpSockMap, args.Verbose)
	if err != nil {
		return err
	}
	return sockops.SetFilter(args.MapDir, "tg_http_filter_map", filters)
}

func (http *httpSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	spec := policy.TpSpec()
	httpParser := &spec.Parser.Http
	if !httpParser.Enable {
		return nil, nil
	}

	if httpParser.Http2 {
		enableHttp2 = true
	} else {
		enableHttp2 = false
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("http sensor does not implement policy filtering")
	}
	filters = ParseHTTPSpec(httpParser)
	if len(filters) > sockops.TLS_MAX_PORTS {
		return nil, fmt.Errorf("HTTP parser only supports up to %d MatchPorts selectors, got %d", sockops.TLS_MAX_PORTS, len(filters))
	}

	if !kernels.MinKernelVersion("5.10") {
		return nil, fmt.Errorf("HTTP parser requires kernel version >= 5.10")
	}

	return EnableHTTPParser(), nil
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

func init() {
	var err error

	moreBytes, err = lru.New[api.HttpKey, *httpproto.MsgHttpEventUnix](moreBytesCacheSize)
	if err != nil {
		logger.GetLogger().Errorf("HTTP More bytes cache failed, may drop data: %s\n", err)
		moreBytesEnable = false
	} else {
		moreBytesEnable = true
	}

	aggregate, err = lru.New[api.HttpKey, *httpproto.MsgHttpEventUnix](cacheSize)
	if err != nil {
		logger.GetLogger().Errorf("HTTP aggregation disabled: %s\n", err)
		aggregateEnable = false
	} else {
		aggregateEnable = true
	}

	http2StateCache, err = lru.New[networkapi.MsgIPTuple, *http2State](http2StateCacheSize)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}

	http := &httpSensor{
		name: "skmsg http sensor",
	}

	if utils.SkSkbParserRequired() {
		skskbParser := &skSkbParserSensor{
			name: "skskb parser http sensor",
		}
		sensors.RegisterProbeType("http_skskb_parser", skskbParser)
	}

	skskbVerdict := &skSkbVerdictSensor{
		name: "skskb verdict http sensor",
	}

	sensors.RegisterProbeType("http_skskb_verdict", skskbVerdict)
	sensors.RegisterProbeType("http_skmsg", http)

	sensors.RegisterPolicyHandlerAtInit(http.name, http)
	observer.RegisterEventHandlerAtInit(ops.MSG_OP_HTTP, handleHTTP)
}

/* Add sensor from CRD */
func EnableHTTPParser() *sensors.Sensor {
	logger.GetLogger().Infof("Enable HTTP")

	progs := []*program.Program{
		Skmsg,
		SkSkbVerdict,
	}

	if utils.SkSkbParserRequired() {
		progs = append(progs, SkSkbParser)
	}

	maps := []*program.Map{
		TailCalls,
		SkbTailCalls,
		HTTPContext,
		HTTPFilterMap,
		HttpErrorMap,
		sockops.HttpSockMap,
		sockops.TlsSockMap,
		sockops.NopSockMap,
		SocketMap, SocketStats,
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

// ParseHTTPSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
func ParseHTTPSpec(spec *v1alpha1.HttpSpec) []uint32 {
	var ports []uint32

	for _, selector := range spec.Selectors {
		ports = append(ports, selector.MatchPorts...)
	}

	return ports
}

var (
	RequestDone             = uint32(0)
	RequestURL              = uint32(1)
	RequestHost             = uint32(2)
	RequestProtocol         = uint32(3)
	RequestUserAgent        = uint32(5)
	RequestContentLength    = uint32(6)
	RequestUnknown          = uint32(7)
	ResponseProtocol        = uint32(8)
	ResponseCode            = uint32(9)
	ResponseReason          = uint32(10)
	HTTP2HeaderFrame        = uint32(11)
	RequestTransferEncoding = uint32(12)

	MethodError    = uint32(0)
	MethodConnect  = uint32(1)
	MethodDelete   = uint32(2)
	MethodGet      = uint32(3)
	MethodHead     = uint32(4)
	MethodOptions  = uint32(5)
	MethodPost     = uint32(6)
	MethodPut      = uint32(7)
	MethodPatch    = uint32(8)
	MethodTrace    = uint32(9)
	MethodUnknown  = uint32(10)
	MethodResponse = uint32(11)
	MethodPRI      = uint32(12)
)

/* HTTP Event handler */
func handleHTTP(r *bytes.Reader) ([]observer.Event, error) {
	m := &api.MsgHttpEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), m)
	if err != nil {
		return nil, err
	}
	return msgToHTTPEventUnix(m, r)
}

func msgToHTTPEventUnix(m *api.MsgHttpEvent, r *bytes.Reader) ([]observer.Event, error) {
	unix := &httpproto.MsgHttpEventUnix{
		Msg: m,
	}

	if m.Request.Length > HTTP_CLAMP_URL_LENGTH {
		logger.GetLogger().WithFields(logrus.Fields{
			"length": m.Request.Length,
			"saddr":  networkapi.GetIP(m.Tuple.SAddr, m.Common.Op, m.Tuple.IPv6 != 0).String(),
			"daddr":  networkapi.GetIP(m.Tuple.DAddr, m.Common.Op, m.Tuple.IPv6 != 0).String(),
			"sport":  m.Tuple.SPort,
			"dport":  m.Tuple.DPort,
		}).Warnf("url length %d would exceed %d", m.Request.Length, HTTP_CLAMP_URL_LENGTH)
	}

	url := make([]byte, min(int(m.Request.Length), HTTP_CLAMP_URL_LENGTH))
	if _, err := r.Read(url); err != nil {
		logger.GetLogger().WithError(err).Warnf("HTTP URL read error")
		return nil, err
	}

	switch m.Request.Method {
	case MethodPRI:
		if !enableHttp2 {
			return nil, nil
		}
		return http2ToHTTPEventUnix(m, url)
	case MethodResponse:
		unix.Request.RequestId = m.Request.RespId
	default:
		unix.Request.RequestId = m.Request.ReqId
	}

	unix.Request.Method = readerhttp.GetHttpMethod(m.Request.Method)
	unix.Request.Flags = m.Request.Flags

	// Clear the direction bit for HTTP/1.1. It's needed for HTTP/2 to have per-direction
	// header decoders.
	unix.Msg.Tuple.Proto = 0

	key := api.HttpKey{
		Tuple: unix.Msg.Tuple,
		Id:    unix.Request.RequestId,
	}
	usedMoreBytes := uint32(0)

	if moreBytesEnable {
		entry, ok := moreBytes.Get(key)
		if ok {
			unix = entry
			moreBytes.Remove(key)
			usedMoreBytes |= readerhttp.HttpMultiMessage
		}
	}

	iter := chunks.NewTypedChunkIterator(url[:])

	for {
		chunk, typ, ok := iter.NextString()
		if !ok {
			break
		}

		switch typ {
		case RequestURL:
			unix.Request.Uri = chunk
		case RequestProtocol:
			unix.Request.Protocol = chunk
		case RequestHost:
			unix.Request.Host = strings.TrimSpace(chunk)
		case RequestUserAgent:
			unix.Request.UserAgent = chunk
		case RequestContentLength:
			if m.Request.Method == MethodResponse {
				unix.Request.RespContentLength = chunk
			} else {
				unix.Request.ContentLength = chunk
			}
		case RequestTransferEncoding:
			if m.Request.Method == MethodResponse {
				unix.Request.RespTransferEncoding = strings.TrimSpace(chunk)
			} else {
				unix.Request.TransferEncoding = strings.TrimSpace(chunk)
			}
		case ResponseProtocol:
			unix.Request.RespVersion = chunk
		case ResponseCode:
			unix.Request.Code = chunk
		case ResponseReason:
			unix.Request.Reason = chunk
		case RequestUnknown:
			continue
		default:
			return nil, fmt.Errorf("unhandled HTTP payload type: %d", typ)
		}
	}
	if err := iter.Err(); err != nil {
		logger.GetLogger().Debugf("Error iterating HTTP data: %s", err)
		unix.Request.Flags = iter.ErrorToCode()
	}

	// If aggregation is disabled just push events as we see them.
	// Workaround kernel bug for HTTPS while waiting for upstream kernel fix
	// to land. Instead of spending time to work out per port disabling just
	// hard code and we will revert when fix lands.
	if !aggregateEnable || unix.Msg.Tuple.DPort == 47873 {
		return []observer.Event{unix}, nil
	}

	if httpNeedsMoreBytes(m.Request.Flags) {
		moreBytes.Add(key, unix)
		return nil, nil
	}

	/* If this is not a response then its a request and we need to cache it
	 * until we get a response so we can merge the request/response.
	 */
	if m.Request.Method != MethodResponse {
		entry, ok := aggregate.Get(key)
		if !ok {
			aggregate.Add(key, unix)
			return nil, nil
		}
		unix.Request.Code = entry.Request.Code
		unix.Request.Reason = entry.Request.Reason
		unix.Request.RespContentLength = entry.Request.RespContentLength
		unix.Request.RespTransferEncoding = entry.Request.RespTransferEncoding
		aggregate.Remove(key)
	} else {
		entry, ok := aggregate.Get(key)
		if ok {
			unix.Request.Method = entry.Request.Method
			unix.Request.Uri = entry.Request.Uri
			unix.Request.Host = entry.Request.Host
			unix.Request.Protocol = entry.Request.Protocol
			unix.Request.UserAgent = entry.Request.UserAgent
			unix.Request.ContentLength = entry.Request.ContentLength
			unix.Request.TransferEncoding = entry.Request.TransferEncoding
			unix.Request.Ktime = entry.Msg.Common.Ktime
			unix.Request.FlagsResponse = entry.Request.Flags | usedMoreBytes
			unix.Msg.ProcessKey = entry.Msg.ProcessKey
			aggregate.Remove(key)
		} else {
			/* Response seen before request, stash the response and wait for request. */
			aggregate.Add(key, unix)
			return nil, nil
		}
	}
	return []observer.Event{unix}, nil
}

// http2State is the state required to decode header frames. Specific to a connection and direction.
type http2State struct {
	decoder    *hpack.Decoder
	reader     *bytes.Reader
	framer     *http2.Framer
	frameQueue *http2FrameQueue
}

func http2ToHTTPEventUnix(m *api.MsgHttpEvent, url []byte) ([]observer.Event, error) {
	state, ok := http2StateCache.Get(m.Tuple)
	if !ok {
		reader := bytes.NewReader(nil)
		state = &http2State{
			reader:     reader,
			decoder:    hpack.NewDecoder(4096, nil),
			framer:     http2.NewFramer(nil, reader),
			frameQueue: newHttp2FrameQueue(frameQueueSize, 1),
		}
		http2StateCache.Add(m.Tuple, state)
	}

	// Push the header frame into the queue for ordering.
	state.frameQueue.push(m)

	events := make([]observer.Event, 0, 16)
	for {
		// Pop frames from the queue in order.
		m := state.frameQueue.pop()
		if m == nil {
			break
		}
		iter := chunks.NewTypedChunkIterator(url[:])

		for {
			chunk, typ, ok := iter.Next()
			if !ok {
				break
			}

			if typ != HTTP2HeaderFrame {
				return nil, fmt.Errorf("unexpected chunk type in event: %d, expected %d", typ, HTTP2HeaderFrame)
			}

			unix := &httpproto.MsgHttpEventUnix{
				Msg: m,
			}
			unix.Request.Flags = m.Request.Flags

			if state.handleHttp2HeaderFrame(unix, chunk) {
				events = append(events, unix)
			}
		}
	}
	return events, nil
}

func (s *http2State) handleHttp2HeaderFrame(unix *httpproto.MsgHttpEventUnix, frameBytes []byte) bool {
	s.reader.Reset(frameBytes)

	frame, err := s.framer.ReadFrame()
	if err != nil {
		logger.GetLogger().Printf("HTTP2: failed to read frame: %v (key: %v)\n", err, unix.Msg.Tuple)
		return false
	}

	headers, ok := frame.(*http2.HeadersFrame)
	if !ok {
		return false
	}

	s.decoder.SetEmitEnabled(true)
	s.decoder.SetMaxStringLength(256 /* XXX */)
	defer s.decoder.SetEmitFunc(func(_ hpack.HeaderField) {})
	s.decoder.SetEmitFunc(func(field hpack.HeaderField) {
		switch field.Name {
		case ":method":
			unix.Request.Method = field.Value
		case ":status":
			unix.Request.Code = field.Value
			if code, err := strconv.ParseInt(field.Value, 10, 32); err == nil {
				unix.Request.Reason = http.StatusText(int(code))
			}
		case ":authority":
			unix.Request.Host = field.Value
		case ":path":
			unix.Request.Uri = field.Value
		case "user-agent":
			unix.Request.UserAgent = field.Value
		case "content-length":
			unix.Request.ContentLength = field.Value
			unix.Request.RespContentLength = field.Value
		}
	})

	if _, err = s.decoder.Write(headers.HeaderBlockFragment()); err != nil {
		logger.GetLogger().Warnf("HTTP2: failed to decode frame: %s (key: %v)\n", err, unix.Msg.Tuple)
		// Keep going as the decoding error may have been due to a lost event desyncing
		// the header compression and we may have partially succeeded in decoding some of the headers.
		// Better to emit the events with partial data than drop them completely. It's also likely
		// that the interesting header fields were correctly decoded.
	}

	if err := s.decoder.Close(); err != nil {
		logger.GetLogger().Warnf("HTTP2: failed to reset decoder: %s\n", err)
	}

	streamId := headers.Header().StreamID
	isRequest := unix.Request.Code == ""

	unix.Msg.Tuple.Proto = 0

	unix.Request.Protocol = "HTTP/2"
	unix.Request.RespVersion = "HTTP/2"

	key := api.HttpKey{
		Tuple: unix.Msg.Tuple,
		Id:    uint64(streamId),
	}

	if isRequest {
		entry, ok := aggregate.Get(key)
		if !ok {
			aggregate.Add(key, unix)
			return false
		}
		unix.Request.Code = entry.Request.Code
		unix.Request.Reason = entry.Request.Reason
		unix.Request.RespContentLength = entry.Request.RespContentLength
		aggregate.Remove(key)
	} else {
		entry, ok := aggregate.Get(key)
		if ok {
			unix.Request.Method = entry.Request.Method
			unix.Request.Uri = entry.Request.Uri
			unix.Request.Host = entry.Request.Host
			unix.Request.UserAgent = entry.Request.UserAgent
			unix.Request.Ktime = entry.Msg.Common.Ktime
			unix.Request.ContentLength = entry.Request.ContentLength
			unix.Msg.ProcessKey = entry.Msg.ProcessKey
			aggregate.Remove(key)
		} else {
			/* Response seen before request, stash the response and wait for request. */
			aggregate.Add(key, unix)
			return false
		}
	}
	return true
}
