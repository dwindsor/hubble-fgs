// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package encoder

import (
	"bytes"
	"os"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestCompactEncoder_InvalidEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the event field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{})
	assert.Error(t, err)
}

func TestCompactEncoder_ExecEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{},
		},
	})
	assert.Error(t, err)

	// without pod info
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process my-node /usr/bin/curl isovalent.com", result)

	// with pod info
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/hubble-enterprise /usr/bin/curl isovalent.com", result)
}

func TestCompactEncoder_ConnectEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port fields are nil
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Protocol:      tetragon.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔌 connect my-node /usr/bin/curl TCP 1.2.3.4:0 => 5.6.7.8:0", result)

	// with pod info and dns name
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessConnect{
			ProcessConnect: &tetragon.ProcessConnect{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod:    &tetragon.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:         "1.2.3.4",
				SourcePort:       &wrapperspb.UInt32Value{Value: 56789},
				DestinationIp:    "5.6.7.8",
				DestinationPort:  &wrapperspb.UInt32Value{Value: 80},
				DestinationNames: []string{"isovalent.com"},
				Protocol:         tetragon.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔌 connect my-ns/my-pod /usr/bin/curl TCP 1.2.3.4:56789 => 5.6.7.8:80 [isovalent.com]", result)
}

func TestCompactEncoder_AcceptEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessAccept{
			ProcessAccept: &tetragon.ProcessAccept{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port fields are nil
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessAccept{
			ProcessAccept: &tetragon.ProcessAccept{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Protocol:      tetragon.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "💡 accept  my-node /usr/bin/nginx TCP 5.6.7.8:0 => 1.2.3.4:0", result)

	// with pod info and dns name
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessAccept{
			ProcessAccept: &tetragon.ProcessAccept{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &tetragon.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:         "1.2.3.4",
				SourcePort:       &wrapperspb.UInt32Value{Value: 80},
				DestinationIp:    "5.6.7.8",
				DestinationPort:  &wrapperspb.UInt32Value{Value: 56789},
				DestinationNames: []string{"isovalent.com"},
				Protocol:         tetragon.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💡 accept  my-ns/my-pod /usr/bin/nginx TCP 5.6.7.8:56789 => 1.2.3.4:80 [isovalent.com]", result)
}

func TestCompactEncoder_ListenEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessListen{
			ProcessListen: &tetragon.ProcessListen{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port field is nil
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessListen{
			ProcessListen: &tetragon.ProcessListen{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
				},
				Ip:       "0.0.0.0",
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🎧 listen  my-node /usr/bin/nginx TCP 0.0.0.0:0", result)

	// with pod info
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessListen{
			ProcessListen: &tetragon.ProcessListen{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &tetragon.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				Ip:       "0.0.0.0",
				Port:     &wrapperspb.UInt32Value{Value: 80},
				Protocol: tetragon.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🎧 listen  my-ns/my-pod /usr/bin/nginx TCP 0.0.0.0:80", result)
}

func TestCompactEncoder_CloseEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessClose{
			ProcessClose: &tetragon.ProcessClose{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port field is nil
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessClose{
			ProcessClose: &tetragon.ProcessClose{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Stats:         nil,
				Protocol:      tetragon.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "\U0001F9F9 close   my-node /usr/bin/nginx TCP 1.2.3.4:0 => 5.6.7.8:0 tx  rx ", result)

	// with pod info
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessClose{
			ProcessClose: &tetragon.ProcessClose{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &tetragon.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:        "1.2.3.4",
				SourcePort:      &wrapperspb.UInt32Value{Value: 56789},
				DestinationIp:   "5.6.7.8",
				DestinationPort: &wrapperspb.UInt32Value{Value: 80},
				Protocol:        tetragon.SocketProtocol_TCP,
				Stats: &tetragon.SocketStats{
					BytesSent:     1111,
					BytesReceived: 2222,
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "\U0001F9F9 close   my-ns/my-pod /usr/bin/nginx TCP 1.2.3.4:56789 => 5.6.7.8:80 tx 1.1 kB rx 2.2 kB", result)
}

func TestCompactEncoder_SockstatsEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &tetragon.ProcessSockStats{},
		},
	})
	assert.Error(t, err)

	// should fail if socket field is nil
	_, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &tetragon.ProcessSockStats{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// should fail if stats field is nil
	_, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &tetragon.ProcessSockStats{
				Process: &tetragon.Process{
					Binary: "/usr/bin/nginx",
				},
				Socket: &tetragon.SockInfo{},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// with socket and stats fields
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &tetragon.ProcessSockStats{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Socket: &tetragon.SockInfo{
					SourceIp:        "1.2.3.4",
					SourcePort:      &wrapperspb.UInt32Value{Value: 56789},
					DestinationIp:   "5.6.7.8",
					DestinationPort: &wrapperspb.UInt32Value{Value: 80},
					Protocol:        tetragon.SocketProtocol_TCP,
				},
				Stats: &tetragon.SocketStats{
					BytesSent:     1111,
					BytesReceived: 2222,
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "\U0001F9EE socket  my-node /usr/bin/curl TCP 1.2.3.4:56789 => 5.6.7.8:80 tx 1.1 kB rx 2.2 kB", result)
}

func TestCompactEncoder_DnsEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessDns{
			ProcessDns: &tetragon.ProcessDns{},
		},
	})
	assert.Error(t, err)

	// should fail if dns field is nil
	_, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessDns{
			ProcessDns: &tetragon.ProcessDns{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// with dns info.
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessDns{
			ProcessDns: &tetragon.ProcessDns{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Dns: &tetragon.DnsInfo{
					Names: []string{"isovalent.com"},
					ReturnCode: &wrapperspb.Int32Value{
						Value: 0,
					},
					Ips:         []string{"1.2.3.4"},
					AnswerTypes: []uint32{1},
					Response:    true,
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📖 dns     my-node /usr/bin/curl NOERROR [isovalent.com] [A] [1.2.3.4]", result)

	// multiple answers
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessDns{
			ProcessDns: &tetragon.ProcessDns{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Dns: &tetragon.DnsInfo{
					Names: []string{"cloudtrace.googleapis.com."},
					ReturnCode: &wrapperspb.Int32Value{
						Value: 0,
					},
					Ips:         []string{"142.250.72.234", "142.250.68.106", "142.250.72.138", "142.250.72.170"},
					AnswerTypes: []uint32{1, 1, 1, 1},
					Response:    true,
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📖 dns     my-node /usr/bin/curl NOERROR [cloudtrace.googleapis.com.] [A A A A] [142.250.72.234 142.250.68.106 142.250.72.138 142.250.72.170]", result)

	// DNS request
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessDns{
			ProcessDns: &tetragon.ProcessDns{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Dns: &tetragon.DnsInfo{
					Names:         []string{"isovalent.com."},
					QuestionTypes: []uint32{1},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📖 dns     my-node /usr/bin/curl [isovalent.com.] [A]", result)
}

func TestCompactEncoder_TlsEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_Tls{
			Tls: &tetragon.Tls{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if destination port is nil
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_Tls{
			Tls: &tetragon.Tls{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				DestinationIp:     "1.2.3.4",
				NegotiatedVersion: "tls-version",
				SniName:           "isovalent.com",
				Cipher:            "some-cipher",
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔐 tls     my-node /usr/bin/curl 1.2.3.4:0 isovalent.com tls-version some-cipher", result)

	// with tls info.
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_Tls{
			Tls: &tetragon.Tls{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				DestinationIp:     "1.2.3.4",
				DestinationPort:   wrapperspb.UInt32(443),
				NegotiatedVersion: "tls-version",
				SniName:           "isovalent.com",
				Cipher:            "some-cipher",
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔐 tls     my-node /usr/bin/curl 1.2.3.4:443 isovalent.com tls-version some-cipher", result)
}

func TestCompactEncoder_HttpEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessHttp{
			ProcessHttp: &tetragon.ProcessHttp{},
		},
	})
	assert.Error(t, err)

	// should fail if http is nil
	_, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessHttp{
			ProcessHttp: &tetragon.ProcessHttp{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// http request
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessHttp{
			ProcessHttp: &tetragon.ProcessHttp{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &tetragon.HttpInfo{
					Request: &tetragon.HttpRequest{
						Method:  "GET",
						Uri:     "/index.html",
						Version: "1.1",
						Host:    "isovalent.com",
					},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🌐 http    my-node /usr/bin/curl isovalent.com GET /index.html ", result)

	// http response
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessHttp{
			ProcessHttp: &tetragon.ProcessHttp{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &tetragon.HttpInfo{
					Request: &tetragon.HttpRequest{
						Method:  "GET",
						Uri:     "/index.html",
						Version: "1.1",
						Host:    "isovalent.com",
					},
					Response: &tetragon.HttpResponse{
						Code:   200,
						Reason: "ok",
					},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🌐 http    my-node /usr/bin/curl isovalent.com GET /index.html 200 ok 0s", result)

	// http response with duration
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessHttp{
			ProcessHttp: &tetragon.ProcessHttp{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &tetragon.HttpInfo{
					Request: &tetragon.HttpRequest{
						Method:  "GET",
						Uri:     "/index.html",
						Version: "1.1",
						Host:    "isovalent.com",
					},
					Response: &tetragon.HttpResponse{
						Code:   200,
						Reason: "ok",
					},
					Latency: &durationpb.Duration{Seconds: 1},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🌐 http    my-node /usr/bin/curl isovalent.com GET /index.html 200 ok 1s", result)
}

func TestCompactEncoder_ExitEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{},
		},
	})
	assert.Error(t, err)

	// with status
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				Status: 1,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/hubble-enterprise /usr/bin/curl isovalent.com 1", result)

	// with signal
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				Signal: "SIGKILL",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/hubble-enterprise /usr/bin/curl isovalent.com SIGKILL", result)
}

func TestCompactEncoder_KprobeEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// should fail without process field
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.Error(t, err)

	// unknown function
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "⁉️ syscall kube-system/hubble-enterprise /usr/bin/curl unhandled_function", result)
}

func TestCompactEncoder_KprobeOpenEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// open without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "fd_install",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/hubble-enterprise /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "fd_install",
				Args: []*tetragon.KprobeArgument{
					nil,
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeWriteEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// write without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_write",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/hubble-enterprise /usr/bin/curl  ", result)

	// write with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_write",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
					nil,
					{Arg: &tetragon.KprobeArgument_SizeArg{SizeArg: 1234}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/hubble-enterprise /usr/bin/curl /etc/password 1234 bytes", result)
}

func TestCompactEncoder_KprobeCloseEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// open without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_close",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/hubble-enterprise /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_close",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_Encode(t *testing.T) {
	var b bytes.Buffer
	p := NewEnterpriseEncoder(&b, encoder.Never, false)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	assert.Error(t, err)

	// valid event
	err = p.Encode(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/hubble-enterprise /usr/bin/curl isovalent.com\n", b.String())
}

func TestCompactEncoder_InterfaceStatsEventToString(t *testing.T) {
	p := NewEnterpriseEncoder(os.Stdout, encoder.Never, false)

	// open without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_InterfaceStats{
			InterfaceStats: &tetragon.InterfaceStats{
				InterfaceName:    "lo",
				InterfaceIfindex: 1,
				BytesSent:        12345,
				BytesReceived:    67890,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📒 netstat my-node lo@1 tx 12 kB rx 68 kB", result)
}

func TestCompactEncoder_EncodeWithTimestamp(t *testing.T) {
	var b bytes.Buffer
	p := NewEnterpriseEncoder(&b, encoder.Never, true)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	assert.Error(t, err)

	// valid event
	err = p.Encode(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
			},
		},
		Time: &timestamppb.Timestamp{},
	})
	assert.NoError(t, err)
	assert.Equal(t, "1970-01-01T00:00:00.000000000Z 🚀 process kube-system/hubble-enterprise /usr/bin/curl isovalent.com\n", b.String())
}
