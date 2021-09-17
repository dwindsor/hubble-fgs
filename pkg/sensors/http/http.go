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

	// Per-connection HTTP2 header decoders. Required to maintain compression state over the
	// lifetime of the connection.
	decoders2          *lru.Cache
	decoders2CacheSize = 1024
)

var (
	Skmsg = observer.BpfLoadBuilder(
		"bpf_http.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"http_skmsg")

	SkSkbParser = observer.BpfLoadBuilder(
		"bpf_http_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_http_parser/fgshttp",
		"sk_skb_parser",

		false,
		true,
		"sk_skb_parser")

	SkSkbVerdict = observer.BpfLoadBuilder(
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
	SockMap         = observer.BpfMapBuilder(httpSockMapName, "sockops", sockops.ObserverSockopsEstablished)
	TailCalls       = observer.BpfMapBuilder("http1_calls", "http_skmsg", Skmsg)
	SkbTailCalls    = observer.BpfMapBuilder("http1_calls_skb", "sk_skb_verdict", SkSkbVerdict)
	HTTPContext     = observer.BpfMapBuilder("http_map", "http_skmsg", Skmsg)
)

type sensor struct {
	name string
}

func (sockops *sensor) LoadProbe(args observer.LoadProbeArgs) (error, int) {
	path := filepath.Join(args.MapDir, httpSockMapName)
	err, i := observer.ObserverLoadSkmsg(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, path)
	if err != nil {
		return err, i
	}

	if utils.SkSkbParserRequired() {
		err, i = observer.ObserverLoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, SkSkbParser, args.Version, args.Verbose, args.X64, path)
		if err != nil {
			return err, i
		}
	}
	return observer.ObserverLoadSkSkbVerdict(args.BPFDir, args.MapDir, args.CiliumDir, SkSkbVerdict, args.Version, args.Verbose, args.X64, path)
}

func (tls *sensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return AddHTTPSensor(spec.Parser)
}

type skSkbVerdictSensor struct {
	name string
}

func (skSkbVerdict *skSkbVerdictSensor) LoadProbe(args observer.LoadProbeArgs) (error, int) {
	return observer.ObserverLoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, httpSockMapName))
}

func (skmsg *skSkbVerdictSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
	return nil, nil
}

type skSkbParserSensor struct {
	name string
}

func (skSkbParser *skSkbParserSensor) LoadProbe(args observer.LoadProbeArgs) (error, int) {
	return observer.ObserverLoadSkSkb(args.BPFDir, args.MapDir, args.CiliumDir, args.Load, args.Version, args.Verbose, args.X64, filepath.Join(args.MapDir, httpSockMapName))
}

func (skmsg *skSkbParserSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*observer.ObserverSensor, error) {
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

	decoders2, err = lru.New(decoders2CacheSize)
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
		observer.RegisterProbeType("http_skskb_parser", skskbParser)
	}

	skskbVerdict := &skSkbVerdictSensor{
		name: "skskb verdict http sensor",
	}
	observer.RegisterProbeType("http_skskb_verdict", skskbVerdict)

	observer.RegisterProbeType("http_skmsg", skmsg)

	observer.RegisterTracingSensorsAtInit(skmsg.name, skmsg)
	observer.RegisterEventHandlerAtInit(api.MSG_OP_HTTP, handleHTTP)
}

/* Add sensor from CRD */
func EnableHTTPParser() *observer.ObserverSensor {
	logger.GetLogger().Infof("Enable HTTP")

	progs := []*observer.BpfLoad{
		Skmsg,
		SkSkbVerdict,
	}

	if utils.SkSkbParserRequired() {
		progs = append(progs, SkSkbParser)
	}

	maps := []*observer.ObserverMap{
		SockMap,
		TailCalls,
		SkbTailCalls,
		HTTPContext,
	}

	return observer.SensorBuilder("__parser_sensors__", progs, maps)
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

func AddHTTPSensor(parser v1alpha1.ParserPolicySpec) (*observer.ObserverSensor, error) {
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
func msgToHTTPEventUnix(m *api.MsgHttpEvent) (*api.MsgHttpEventUnix, error) {
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
		return unix, nil
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
	return unix, nil
}

func http2ToHTTPEventUnix(m *api.MsgHttpEvent, unix *api.MsgHttpEventUnix) (*api.MsgHttpEventUnix, error) {
	iter := reader.NewTypedChunkIterator(m.Request.Url[:])
	emit := false

	for {
		chunk, typ, ok := iter.Next()
		if !ok {
			break
		}

		if typ != HTTP2HeaderFrame {
			// TODO log error etc.
			return nil, nil
		}
		emit = emit || handleHttp2HeaderFrame(unix, chunk)
	}
	if emit {
		return unix, nil
	} else {
		return nil, nil
	}
}

func handleHTTP(r *bytes.Reader) (interface{}, error) {
	var m *api.MsgHttpEvent

	m = &api.MsgHttpEvent{}
	err := binary.Read(r, native_endian.NativeEndian(), m)
	if err != nil {
		return nil, err
	}

	u, err := msgToHTTPEventUnix(m)
	if u == nil {
		return nil, err
	}
	return u, err
}

func handleHttp2HeaderFrame(unix *api.MsgHttpEventUnix, frameBytes []byte) bool {
	r := bytes.NewReader(frameBytes)
	framer := http2.NewFramer(nil, r)

	if f, ok := decoders2.Get(unix.Tuple); ok {
		framer.ReadMetaHeaders = f.(*hpack.Decoder)
	} else {
		framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
		decoders2.Add(unix.Tuple, framer.ReadMetaHeaders)
	}

	frame, err := framer.ReadFrame()
	if err != nil {
		logger.GetLogger().Printf("HTTP2: failed to read frame: %v (key: %v)\n", err, unix.Tuple)
		return false
	}

	headers, ok := frame.(*http2.MetaHeadersFrame)
	if !ok {
		return false
	}

	streamId := headers.Header().StreamID
	for _, field := range headers.Fields {
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
			unix.Request.ContentLength = field.Value
		}
	}

	isRequest := unix.Tuple.Proto == 0
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
			unix.Request.ContentLength = r.Request.ContentLength
			unix.Request.Ktime = r.Common.Ktime
			unix.ProcessKey = r.ProcessKey
			aggregate.Remove(key)
		}
		return true
	}
}
