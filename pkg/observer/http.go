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
	"path/filepath"

	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"

	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/reader"
	"github.com/isovalent/hubble-fgs/pkg/selectors"

	lru "github.com/hashicorp/golang-lru"
)

var (
	httpSelectors [128]byte

	// Runtime aggregation of request/response
	httpAggregate       *lru.Cache
	httpAggregateEnable bool
	httpCacheSize       = 1024
)

var (
	ObserverHttpSkmsg = BpfLoadBuilder(
		"bpf_http.o",
		"sk_msg",
		"sk_msg",
		"sk_msg/fgs",
		"sk_msg_fgs",

		false,
		true,
		"http_skmsg")

	ObserverHttpSkSkbParser = BpfLoadBuilder(
		"bpf_http_parser.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_http_parser/fgshttp",
		"sk_skb_parser",

		false,
		true,
		"sk_skb_parser")

	ObserverHttpSkSkbVerdict = BpfLoadBuilder(
		"bpf_http_verdict.o",
		"sk_skb",
		"sk_skb",
		"sk_skb_http_verdict/fgshttp",
		"sk_skb_verdict",

		false,
		true,
		"sk_skb_verdict")

	/* Http maps */
	httpSockMapName          = "http_sock_map"
	ObserverHttpSockMap      = BpfMapBuilder(httpSockMapName, "sockops", ObserverSockopsEstablished)
	ObserverHttpTailCalls    = BpfMapBuilder("http1_calls", "http_skmsg", ObserverHttpSkmsg)
	ObserverHttpSkbTailCalls = BpfMapBuilder("http1_calls_skb", "sk_skb_verdict", ObserverHttpSkSkbVerdict)
	ObserverHttpContext      = BpfMapBuilder("http_map", "http_skmsg", ObserverHttpSkmsg)
)

type observerHttpSensor struct {
	name string
}

func (sockops *observerHttpSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad, version, verbose int,
	x64 bool,
) (error, int) {
	path := filepath.Join(mapDir, httpSockMapName)
	err, i := ObserverLoadSkmsg(bpfDir, mapDir, ciliumDir, load, version, 0, x64, path)
	if err != nil {
		return err, i
	}

	if skSkbParserRequired() {
		err, i = ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, ObserverHttpSkSkbParser, version, 0, x64, path)
		if err != nil {
			return err, i
		}
	}
	return ObserverLoadSkSkbVerdict(bpfDir, mapDir, ciliumDir, ObserverHttpSkSkbVerdict, version, 0, x64, path)
}

func (tls *observerHttpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return getSensorFromParserPolicy(spec)
}

type observerSkSkbVerdictHttpSensor struct {
	name string
}

func (skSkbVerdict *observerSkSkbVerdictHttpSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, httpSockMapName))
}

func (skmsg *observerSkSkbVerdictHttpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

type observerSkSkbParserHttpSensor struct {
	name string
}

func (skSkbParser *observerSkSkbParserHttpSensor) LoadProbe(
	bpfDir, mapDir, ciliumDir string,
	load *BpfLoad,
	version, verbose int, x64 bool) (error, int) {
	return ObserverLoadSkSkb(bpfDir, mapDir, ciliumDir, load, version, verbose, x64, filepath.Join(mapDir, httpSockMapName))
}

func (skmsg *observerSkSkbParserHttpSensor) SpecHandler(spec *v1alpha1.TracingPolicySpec) (*ObserverSensor, error) {
	return nil, nil
}

func init() {
	AddHttp()
}

func AddHttp() {
	var err error

	httpAggregate, err = lru.New(httpCacheSize)
	if err != nil {
		logger.GetLogger().Errorf("HTTP aggregation disabled: %s\n", err)
		httpAggregateEnable = false
	} else {
		httpAggregateEnable = true
	}

	skmsg := &observerHttpSensor{
		name: "skmsg http sensor",
	}

	if skSkbParserRequired() {
		skskbParser := &observerSkSkbParserHttpSensor{
			name: "skskb parser http sensor",
		}
		RegisterProbeType("http_skskb_parser", skskbParser)
	}

	skskbVerdict := &observerSkSkbVerdictHttpSensor{
		name: "skskb verdict http sensor",
	}
	RegisterProbeType("http_skskb_verdict", skskbVerdict)

	RegisterProbeType("http_skmsg", skmsg)

	RegisterTracingSensorsAtInit(skmsg.name, skmsg)
	RegisterEventHandlerAtInit(api.MSG_OP_HTTP, handleHttp)
}

/* Add sensor from CRD */
func EnableHttpParser() *ObserverSensor {
	logger.GetLogger().Infof("Enable HTTP")

	progs := []*BpfLoad{
		ObserverHttpSkmsg,
		ObserverHttpSkSkbVerdict,
	}

	if skSkbParserRequired() {
		progs = append(progs, ObserverHttpSkSkbParser)
	}

	maps := []*ObserverMap{
		ObserverHttpSockMap,
		ObserverHttpTailCalls,
		ObserverHttpSkbTailCalls,
		ObserverHttpContext,
	}

	return SensorBuilder("__parser_sensors__", progs, maps)
}

func parseHttpSelector(k *selectors.KernelSelectorState, s v1alpha1.HttpSelector) error {
	return parseMatchPorts(k, s.MatchPorts)
}

// ParseHttpSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
//
// Http selector layout is the following.
//    #OfSelectors         uint32
//    OffsetOfEachSelector uint32
//    #OfMatchPorts        uint32
//    Port1 .... PortN     uint32, uint32, ...
func ParseHttpSpec(spec *v1alpha1.HttpSpec) ([128]byte, error) {
	var match [128]byte
	var e [4096]byte
	k := &selectors.KernelSelectorState{}

	selectors.WriteSelectorUint32(k, uint32(len(spec.Selectors)))
	soff := make([]uint32, len(spec.Selectors))
	for i, _ := range spec.Selectors {
		soff[i] = selectors.AdvanceSelectorLength(k)
	}

	for i, s := range spec.Selectors {
		selectors.WriteSelectorLength(k, soff[i])
		loff := selectors.AdvanceSelectorLength(k)
		if err := parseHttpSelector(k, s); err != nil {
			return match, err
		}
		selectors.WriteSelectorLength(k, loff)
	}

	e = selectors.GetSelectorBuffer(k)
	copy(match[:], e[:128])
	return match, nil
}

func AddHttpSensor(parser v1alpha1.ParserPolicySpec) (*ObserverSensor, error) {
	var err error

	if !parser.Http.Enable {
		return nil, nil
	}

	httpSelectors, err = ParseHttpSpec(&parser.Http)
	if err != nil {
		return nil, err
	}
	return EnableHttpParser(), nil
}

var (
	HttpRequestDone          = uint32(0)
	HttpRequestUrl           = uint32(1)
	HttpRequestHost          = uint32(2)
	HttpRequestProtocol      = uint32(3)
	HttpRequestUserAgent     = uint32(5)
	HttpRequestContentLength = uint32(6)
	HttpRequestUnknown       = uint32(7)
	HttpResponseProtocol     = uint32(8)
	HttpResponseCode         = uint32(9)
	HttpResponseReason       = uint32(10)

	HttpMethodError    = uint32(0)
	HttpMethodConnect  = uint32(1)
	HttpMethodDelete   = uint32(2)
	HttpMethodGet      = uint32(3)
	HttpMethodHead     = uint32(4)
	HttpMethodOptions  = uint32(5)
	HttpMethodPost     = uint32(6)
	HttpMethodPut      = uint32(7)
	HttpMethodPatch    = uint32(8)
	HttpMethodTrace    = uint32(9)
	HttpMethodUnknown  = uint32(10)
	HttpMethodResponse = uint32(11)
)

/* HTTP Event handler */
func msgToHttpEventUnix(m *api.MsgHttpEvent) (*api.MsgHttpEventUnix, error) {
	unix := &api.MsgHttpEventUnix{
		Common:     m.Common,
		Tuple:      m.Tuple,
		ProcessKey: m.ProcessKey,
	}

	unix.Request.Method = reader.GetHttpMethod(m.Request.Method)
	if m.Request.Method == HttpMethodResponse {
		unix.Request.RequestId = m.Request.RespId
	} else {
		unix.Request.RequestId = m.Request.ReqId
	}

	offset := uint32(0)
	ty := uint32(m.Request.Url[offset])

	for ty != 0 {
		sz := uint32(m.Request.Url[offset+4])

		start := 8 + offset
		end := 8 + offset + sz

		switch ty {
		case HttpRequestUrl:
			unix.Request.Uri = string(m.Request.Url[start:end])
		case HttpRequestProtocol:
			unix.Request.Protocol = string(m.Request.Url[start:end])
		case HttpRequestHost:
			unix.Request.Host = string(m.Request.Url[start:end])
		case HttpRequestUserAgent:
			unix.Request.UserAgent = string(m.Request.Url[start:end])
		case HttpRequestContentLength:
			if m.Request.Method == HttpMethodResponse {
				unix.Request.RespContentLength = string(m.Request.Url[start:end])
			} else {
				unix.Request.ContentLength = string(m.Request.Url[start:end])
			}
		case HttpResponseProtocol:
			unix.Request.RespVersion = string(m.Request.Url[start:end])
		case HttpResponseCode:
			unix.Request.Code = string(m.Request.Url[start:end])
		case HttpResponseReason:
			unix.Request.Reason = string(m.Request.Url[start:end])
		}
		offset += sz + 8
		ty = uint32(m.Request.Url[offset])
	}

	key := api.HttpKey{
		Tuple: unix.Tuple,
		Id:    unix.Request.RequestId,
	}

	// If aggregation is disabled just push events as we see them.
	if !httpAggregateEnable {
		return unix, nil
	}
	/* If this is not a response then its a request and we need to cache it
	 * until we get a response so we can merge the request/response.
	 */
	if m.Request.Method != HttpMethodResponse {
		httpAggregate.Add(key, unix)
		return nil, nil
	} else {
		entry, ok := httpAggregate.Get(key)
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
			httpAggregate.Remove(key)
		}
	}
	return unix, nil
}

func handleHttp(r *bytes.Reader) (interface{}, error) {
	var m *api.MsgHttpEvent

	m = &api.MsgHttpEvent{}
	err := binary.Read(r, binary.LittleEndian, m)
	if err != nil {
		return nil, err
	}

	u, err := msgToHttpEventUnix(m)
	if u == nil {
		return nil, err
	}
	return u, err
}
