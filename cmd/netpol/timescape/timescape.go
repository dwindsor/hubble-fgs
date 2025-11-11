package timescape

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"iter"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	graphpb "github.com/isovalent/hubble-timescape/api/timescape/graph/v1alpha"
	netpb "github.com/isovalent/ipa/common/net/v1alpha"
	commonpb "github.com/isovalent/ipa/common/time/v1alpha"
	ipagraphpb "github.com/isovalent/ipa/graph/v1alpha"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/isovalent/hubble-fgs/cmd/netpol/model"
	"github.com/isovalent/hubble-fgs/cmd/netpol/types"
)

const (
	srcNetDevIP    = "source.network_device.ip"
	srcNetDevPort  = "source.network_device.port"
	srcNetDevVLAN  = "source.network_device.vlan_id"
	srcNetDevVRF   = "source.network_device.vrf_name"
	srcNetDevProto = "source.network_device.ip_protocol"
	destNetDevIP   = "destination.network_device.ip"
	destNetDevPort = "destination.network_device.port"
	destNetDevVLAN = "destination.network_device.vlan_id"
	destNetDevVRF  = "destination.network_device.vrf_name"
)

type Config struct {
	TimescapeAddress string
	TimescapeCert    string
	TimescapeKey     string
	TimescapeCA      string
}

func (cfg Config) Flags(fs *pflag.FlagSet) {
	fs.String("timescape-address", "localhost:4244", "Timescape server address")
	fs.String("timescape-cert", "", "Timescape client certificate")
	fs.String("timescape-key", "", "Timescape client private key")
	fs.String("timescape-ca", "", "Timescape certificate authoritiy")
}

func (cfg *Config) Parse(fs *pflag.FlagSet) error {
	var err error
	cfg.TimescapeCert, err = fs.GetString("timescape-cert")
	if err != nil {
		return err
	}
	cfg.TimescapeKey, err = fs.GetString("timescape-key")
	if err != nil {
		return err
	}
	cfg.TimescapeCA, err = fs.GetString("timescape-ca")
	if err != nil {
		return err
	}
	cfg.TimescapeAddress, err = fs.GetString("timescape-address")
	if err != nil {
		return err
	}
	return nil
}

type Client struct {
	conn *grpc.ClientConn
}

func NewClient(cfg Config) (*Client, error) {
	if cfg.TimescapeCert != "" {
		return NewTLSClient(cfg.TimescapeAddress, cfg.TimescapeCert, cfg.TimescapeKey, cfg.TimescapeCA)
	}
	return NewInsecureClient(cfg.TimescapeAddress)
}

func NewInsecureClient(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

func NewTLSClient(addr string, certFile, keyFile string, caFiles ...string) (*Client, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}

	capool := x509.NewCertPool()
	for _, caFile := range caFiles {
		if ca, err := os.ReadFile(caFile); err != nil {
			return nil, err
		} else if !capool.AppendCertsFromPEM(ca) {
			return nil, err
		}
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      capool,
	}
	creds := credentials.NewTLS(tlsConfig)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

func (c *Client) Close() {
	c.conn.Close()
}

func (c *Client) GetConnections(ctx context.Context, since, until time.Time, filter *model.Filter) (iter.Seq[types.Flow], error) {
	client := graphpb.NewGraphServiceClient(c.conn)

	linkType := (&ipagraphpb.VertexFamilyNetworkDevice{}).ProtoReflect().Descriptor().Index()

	req := graphpb.GetConnectionsRequest{
		Window: &commonpb.Range{
			Since: timestamppb.New(since),
			Until: timestamppb.New(until),
		},
		LinkType: uint32(linkType),
		Filter:   FilterToCEL(filter),
		GroupBySource: []string{
			srcNetDevIP,
			srcNetDevPort,
			srcNetDevVLAN,
			srcNetDevVRF,
			srcNetDevProto,
		},
		GroupByDestination: []string{
			destNetDevIP,
			destNetDevPort,
			destNetDevVLAN,
			destNetDevVRF,
		},
	}

	resp, err := client.GetConnections(ctx, &req)
	if err != nil {
		return nil, err
	}

	parseUInt16 := func(s string) uint16 {
		n, _ := strconv.ParseUint(s, 10, 16)
		return uint16(n)
	}

	parseProto := func(protoNumber string) (types.Protocol, bool) {
		num, err := strconv.ParseUint(protoNumber, 10, 16)
		if err != nil {
			return "", false
		}
		switch netpb.IPProtocol(num) {
		case netpb.IPProtocol_IP_PROTOCOL_TCP:
			return types.TCP, true
		case netpb.IPProtocol_IP_PROTOCOL_UDP:
			return types.UDP, true
		case netpb.IPProtocol_IP_PROTOCOL_ICMP, netpb.IPProtocol_IP_PROTOCOL_ICMPV6:
			return types.ICMP, true
		default:
			return "", false
		}

	}

	return func(yield func(types.Flow) bool) {
		for _, c := range resp.Connections {
			srcFields := c.GetSourceFields()
			destFields := c.GetDestinationFields()
			if srcFields == nil || destFields == nil {
				continue
			}
			srcAddr, err := netip.ParseAddr(srcFields["ip"])
			if err != nil {
				continue
			}
			destAddr, err := netip.ParseAddr(destFields["ip"])
			if err != nil {
				continue
			}
			proto, ok := parseProto(srcFields["ip_protocol"])
			if !ok {
				continue
			}
			flow := types.Flow{
				Source:          srcAddr,
				Destination:     destAddr,
				SourcePort:      parseUInt16(srcFields["port"]),
				DestinationPort: parseUInt16(destFields["port"]),
				SourceVlan:      parseUInt16(srcFields["vlan_id"]),
				DestinationVlan: parseUInt16(destFields["vlan_id"]),
				SourceVrf:       srcFields["vrf_name"],
				DestinationVrf:  destFields["vrf_name"],
				Protocol:        proto,
				Action:          types.Unknown,
			}
			if !yield(flow) {
				return
			}
		}
	}, nil
}

func FilterToCEL(f *model.Filter) string {
	or := func(a, b string) string {
		if b == "" {
			return a
		}
		return a + " || " + b
	}
	ipInRange := func(which string, prefix netip.Prefix) string {
		if !prefix.IsValid() || prefix.Bits() == 0 {
			return ""
		}
		return fmt.Sprintf("isIPAddressInRange(%s.network_device.ip, '%s')", which, prefix)
	}
	ports := func(which string, minPort, maxPort uint16) string {
		if minPort == 0 && (maxPort == 0 || maxPort == 65535) {
			return ""
		}
		if minPort == maxPort {
			return fmt.Sprintf("%s.network_device.port == %du", which, minPort)

		}
		return fmt.Sprintf("%[1]s.network_device.port >= %[2]du && %[1]s.network_device.port <= %[3]du", which, minPort, maxPort)
	}
	vlans := func(which string, minVLAN, maxVLAN uint16) string {
		if minVLAN == maxVLAN {
			return fmt.Sprintf("%s.network_device.vlan_id  == %du", which, minVLAN)
		}
		if minVLAN > maxVLAN || minVLAN == 0 && maxVLAN == 4096 {
			return ""
		}
		return fmt.Sprintf("%[1]s.network_device.vlan_id  >= %[2]du && %[1]s.network_device.vlan_id <= %[3]du", which, minVLAN, maxVLAN)
	}
	parts := []string{
		or(ipInRange("source", f.SourceV4Prefix), ipInRange("source", f.SourceV6Prefix)),
		or(ipInRange("destination", f.DestV4Prefix), ipInRange("destination", f.DestV6Prefix)),
		ports("source", f.SourceMinPort, f.SourceMaxPort),
		ports("destination", f.DestMinPort, f.DestMaxPort),
		vlans("source", f.VLANMin, f.VLANMax),
		vlans("destination", f.VLANMin, f.VLANMax),
	}
	var vrfs []string
	for _, vrf := range f.VRFs {
		vrfs = append(vrfs, fmt.Sprintf("source.network_device.vrf_name == '%s' && destination.network_device.vrf_name == '%s'", vrf, vrf))
	}
	parts = append(parts, strings.Join(vrfs, " || "))
	parts = slices.DeleteFunc(parts, func(s string) bool { return s == "" })
	return strings.Join(parts, " && ")
}
