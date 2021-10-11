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
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/observer"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/selectors"
	"github.com/isovalent/hubble-fgs/pkg/sensors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/bpf"
	"github.com/isovalent/hubble-fgs/pkg/sensors/sockops"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"

	lru "github.com/hashicorp/golang-lru"
	"github.com/yalue/native_endian"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var (
	Selectors [128]byte

	// Runtime aggregation of request/response
	aggregate       *lru.Cache
	aggregateEnable bool
	cacheSize       = 1024

	// The per-connection and per-direction HTTP/2 state that is required to decompress the
	// header frames.
	http2StateCache     *lru.Cache
	http2StateCacheSize = 16384

	// Number of frames we can queue. If a HTTP/2 frame with an event sequence number that is
	// beyond 'frameQueueSize' away from the next expected one is received the queue is reset
	// and frames are potentially lost. This may potentially confuse the header decoder and some future
	// frames may fail to decode.
	frameQueueSize = 128
)

var (
	Skmsg = bpf.ProgramBuilder(
		"bpf_http.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"http_skmsg")

	SkSkbParser = bpf.ProgramBuilder(
		"bpf_http_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_http_parser/fgshttp",
		"sk_skb_parser",

		false,
		true,
		"sk_skb_parser")

	SkSkbVerdict = bpf.ProgramBuilder(
		"bpf_http_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_http_verdict/fgshttp",
		"sk_skb_verdict",

		false,
		true,
		"sk_skb_verdict")

	/* Http maps */
	httpSockMapName = "http_sock_map"
	SockMap         = bpf.MapBuilder(httpSockMapName, "sockops", sockops.SockopsEstablished)
	TailCalls       = bpf.MapBuilder("http1_calls", "http_skmsg", Skmsg)
	SkbTailCalls    = bpf.MapBuilder("http1_calls_skb", "sk_skb_verdict", SkSkbVerdict)
	HTTPContext     = bpf.MapBuilder("http_map", "http_skmsg", Skmsg)
)

type sensor struct {
	name string
}

func (sockops *sensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	path := filepath.Join(args.MapDir, httpSockMapName)
	err, i := bpf.LoadSkmsg(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, path)
	if err != nil {
		return err, i
	}

	if utils.SkSkbParserRequired() {
		err, i = bpf.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, SkSkbParser, args.Version, args.Verbose, args.X64, path)
		if err != nil {
			return err, i
		}
	}
	return bpf.LoadSkSkbVerdict(args.BPFDir, args.MapDir, args.CiliumDir, SkSkbVerdict, args.Version, args.Verbose, args.X64, path)
}

func (http *sensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return AddHTTPSensor(spec.Parser)
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return bpf.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, httpSockMapName))
}

func (skmsg *skSkbVerdictSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(args sensors.LoadProbeArgs) (error, int) {
	return bpf.LoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, httpSockMapName))
}

func (skmsg *skSkbParserSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*sensors.Sensor, error) {
	return nil, nil
}

func init() {
	AddHTTP()
}

func AddHTTP() {
	var err error

	aggregate, err = lru.New(cacheSize)
	if err != nil {
		logger.GetLogger().Errorf("HTTP aggregation disabled: %s\n", err)
		aggregateEnable = false
	} else {
		aggregateEnable = true
	}

	http2StateCache, err = lru.New(http2StateCacheSize)
	if err != nil {
		logger.GetLogger().Fatal(err)
	}

	skmsg := &sensor{
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

	sensors.RegisterProbeType("http_skmsg", skmsg)

	sensors.RegisterTracingSensorsAtInit(skmsg.name, skmsg)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_HTTP, handleHTTP)
}

/* Add sensor from CRD */
func EnableHTTPParser() *sensors.Sensor {
	logger.GetLogger().Infof("Enable HTTP")

	progs := []*bpf.Program{
		Skmsg,
		SkSkbVerdict,
	}

	if utils.SkSkbParserRequired() {
		progs = append(progs, SkSkbParser)
	}

	maps := []*bpf.Map{
		SockMap,
		TailCalls,
		SkbTailCalls,
		HTTPContext,
	}

	return sensors.SensorBuilder("__parser_sensors__", progs, maps)
}

func parseHTTPSelector(k *selectors.KernelSelectorState, s v1alpha1.HttpSelector) error {
	return utils.ParseMatchPorts(k, s.MatchPorts)
}

// ParseHTTPSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
//
// Http selector layout is the following.
//    #OfSelectors         uint32
//    OffsetOfEachSelector uint32
//    #OfMatchPorts        uint32
//    Port1 .... PortN     uint32, uint32, ...
func ParseHTTPSpec(spec *v1alpha1.HttpSpec) ([128]byte, error) {
	var match [128]byte
	var e [4096]byte
	k := &selectors.KernelSelectorState{}

	selectors.WriteSelectorUint32(k, uint32(len(spec.Selectors)))
	soff := make([]uint32, len(spec.Selectors))
	for i := range spec.Selectors {
		soff[i] = selectors.AdvanceSelectorLength(k)
	}

	for i, s := range spec.Selectors {
		selectors.WriteSelectorLength(k, soff[i])
		loff := selectors.AdvanceSelectorLength(k)
		if err := parseHTTPSelector(k, s); err != nil {
			return match, err
		}
		selectors.WriteSelectorLength(k, loff)
	}

	e = selectors.GetSelectorBuffer(k)
	copy(match[:], e[:128])
	return match, nil
}

func AddHTTPSensor(parser v1alpha1.ParserPolicySpec) (*sensors.Sensor, error) {
	var err error

	if !parser.Http.Enable {
		return nil, nil
	}

	Selectors, err = ParseHTTPSpec(&parser.Http)
	if err != nil {
		return nil, err
	}
	return EnableHTTPParser(), nil
}

var (
	RequestDone          = uint32(0)
	RequestURL           = uint32(1)
	RequestHost          = uint32(2)
	RequestProtocol      = uint32(3)
	RequestUserAgent     = uint32(5)
	RequestContentLength = uint32(6)
	RequestUnknown       = uint32(7)
	ResponseProtocol     = uint32(8)
	ResponseCode         = uint32(9)
	ResponseReason       = uint32(10)
	HTTP2HeaderFrame     = uint32(11)

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
func handleHTTP(r *bytes.Reader) ([]observer.ObserverEvent, error) {
	m := &api.MsgHttpEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), m)
	if err != nil {
		return nil, err
	}
	return msgToHTTPEventUnix(m)
}

func msgToHTTPEventUnix(m *api.MsgHttpEvent) ([]observer.ObserverEvent, error) {
	unix := &api.MsgHttpEventUnix{
		Common:     m.Common,
		Tuple:      m.Tuple,
		ProcessKey: m.ProcessKey,
	}

	unix.Request.Method = reader.GetHttpMethod(m.Request.Method)

	switch m.Request.Method {
	case MethodPRI:
		return http2ToHTTPEventUnix(m, unix)
	case MethodResponse:
		unix.Request.RequestId = m.Request.RespId
	default:
		unix.Request.RequestId = m.Request.ReqId
	}

	iter := reader.NewTypedChunkIterator(m.Request.Url[:])

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
			unix.Request.Host = chunk
		case RequestUserAgent:
			unix.Request.UserAgent = chunk
		case RequestContentLength:
			if m.Request.Method == MethodResponse {
				unix.Request.RespContentLength = chunk
			} else {
				unix.Request.ContentLength = chunk
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
		logger.GetLogger().Warnf("Error iterating HTTP data: %s", err)
	}

	// Clear the direction bit for HTTP/1.1. It's needed for HTTP/2 to have per-direction
	// header decoders.
	unix.Tuple.Proto = 0

	key := api.HttpKey{
		Tuple: unix.Tuple,
		Id:    unix.Request.RequestId,
	}

	// If aggregation is disabled just push events as we see them.
	if !aggregateEnable {
		return []observer.ObserverEvent{unix}, nil
	}

	/* If this is not a response then its a request and we need to cache it
	 * until we get a response so we can merge the request/response.
	 */
	if m.Request.Method != MethodResponse {
		aggregate.Add(key, unix)
		return nil, nil
	} else {
		entry, ok := aggregate.Get(key)
		if ok {
			r := entry.(*api.MsgHttpEventUnix)
			unix.Request.Method = r.Request.Method
			unix.Request.Uri = r.Request.Uri
			unix.Request.Host = r.Request.Host
			unix.Request.Protocol = r.Request.Protocol
			unix.Request.UserAgent = r.Request.UserAgent
			unix.Request.ContentLength = r.Request.ContentLength
			unix.Request.Ktime = r.Common.Ktime
			unix.ProcessKey = r.ProcessKey
			aggregate.Remove(key)
		}
	}
	return []observer.ObserverEvent{unix}, nil
}

// http2State is the state required to decode header frames. Specific to a connection and direction.
type http2State struct {
	decoder    *hpack.Decoder
	reader     *bytes.Reader
	framer     *http2.Framer
	frameQueue *http2FrameQueue
}

func http2ToHTTPEventUnix(m *api.MsgHttpEvent, unix *api.MsgHttpEventUnix) ([]observer.ObserverEvent, error) {

	var state *http2State
	if x, ok := http2StateCache.Get(m.Tuple); ok {
		state = x.(*http2State)
	} else {
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

	events := make([]observer.ObserverEvent, 0, 16)
	for {
		// Pop frames from the queue in order.
		m := state.frameQueue.pop()
		if m == nil {
			break
		}
		iter := reader.NewTypedChunkIterator(m.Request.Url[:])

		for {
			chunk, typ, ok := iter.Next()
			if !ok {
				break
			}

			if typ != HTTP2HeaderFrame {
				return nil, fmt.Errorf("unexpected chunk type in event: %d, expected %d", typ, HTTP2HeaderFrame)
			}

			if state.handleHttp2HeaderFrame(unix, chunk) {
				events = append(events, unix)
			}
		}
	}
	return events, nil
}

func (s *http2State) handleHttp2HeaderFrame(unix *api.MsgHttpEventUnix, frameBytes []byte) bool {
	s.reader.Reset(frameBytes)

	frame, err := s.framer.ReadFrame()
	if err != nil {
		logger.GetLogger().Printf("HTTP2: failed to read frame: %v (key: %v)\n", err, unix.Tuple)
		return false
	}

	headers, ok := frame.(*http2.HeadersFrame)
	if !ok {
		return false
	}

	isRequest := unix.Tuple.Proto == 0

	s.decoder.SetEmitEnabled(true)
	s.decoder.SetMaxStringLength(256 /* XXX */)
	defer s.decoder.SetEmitFunc(func(hf hpack.HeaderField) {})
	s.decoder.SetEmitFunc(func(field hpack.HeaderField) {
		switch field.Name {
		case ":method":
			unix.Request.Method = field.Value
		case ":status":
			unix.Request.Code = field.Value
		case ":authority":
			unix.Request.Host = field.Value
		case ":path":
			unix.Request.Uri = field.Value
		case "user-agent":
			unix.Request.UserAgent = field.Value
		case "content-length":
			if isRequest {
				unix.Request.ContentLength = field.Value
			} else {
				unix.Request.RespContentLength = field.Value
			}
		}
	})

	if _, err = s.decoder.Write(headers.HeaderBlockFragment()); err != nil {
		logger.GetLogger().Warnf("HTTP2: failed to decode frame: %s (key: %v)\n", err, unix.Tuple)
		// Keep going as the decoding error may have been due to a lost event desyncing
		// the header compression and we may have partially succeeded in decoding some of the headers.
		// Better to emit the events with partial data than drop them completely. It's also likely
		// that the interesting header fields were correctly decoded.
	}

	if err := s.decoder.Close(); err != nil {
		logger.GetLogger().Warnf("HTTP2: failed to reset decoder: %s\n", err)
	}

	streamId := headers.Header().StreamID

	unix.Tuple.Proto = 0

	key := api.HttpKey{
		Tuple: unix.Tuple,
		Id:    uint64(streamId),
	}

	if isRequest {
		aggregate.Add(key, unix)
		return false
	} else {
		entry, ok := aggregate.Get(key)
		if ok {
			r := entry.(*api.MsgHttpEventUnix)
			unix.Request.Method = r.Request.Method
			unix.Request.Uri = r.Request.Uri
			unix.Request.Host = r.Request.Host
			unix.Request.Protocol = r.Request.Protocol
			unix.Request.UserAgent = r.Request.UserAgent
			unix.Request.Ktime = r.Common.Ktime
			unix.Request.ContentLength = r.Request.ContentLength
			unix.ProcessKey = r.ProcessKey
			aggregate.Remove(key)
		}
		return true
	}
}
