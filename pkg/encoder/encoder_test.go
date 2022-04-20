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

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestCompactEncoder_InvalidEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the event field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{})
	assert.Error(t, err)
}

func TestCompactEncoder_ExecEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{},
		},
	})
	assert.Error(t, err)

	// without pod info
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessConnect{
			ProcessConnect: &fgs.ProcessConnect{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port fields are nil
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessConnect{
			ProcessConnect: &fgs.ProcessConnect{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Protocol:      fgs.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔌 connect my-node /usr/bin/curl TCP 1.2.3.4:0 => 5.6.7.8:0", result)

	// with pod info and dns name
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessConnect{
			ProcessConnect: &fgs.ProcessConnect{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod:    &fgs.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:         "1.2.3.4",
				SourcePort:       &wrapperspb.UInt32Value{Value: 56789},
				DestinationIp:    "5.6.7.8",
				DestinationPort:  &wrapperspb.UInt32Value{Value: 80},
				DestinationNames: []string{"isovalent.com"},
				Protocol:         fgs.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🔌 connect my-ns/my-pod /usr/bin/curl TCP 1.2.3.4:56789 => 5.6.7.8:80 [isovalent.com]", result)
}

func TestCompactEncoder_AcceptEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessAccept{
			ProcessAccept: &fgs.ProcessAccept{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port fields are nil
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessAccept{
			ProcessAccept: &fgs.ProcessAccept{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Protocol:      fgs.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "💡 accept  my-node /usr/bin/nginx TCP 5.6.7.8:0 => 1.2.3.4:0", result)

	// with pod info and dns name
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessAccept{
			ProcessAccept: &fgs.ProcessAccept{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &fgs.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:         "1.2.3.4",
				SourcePort:       &wrapperspb.UInt32Value{Value: 80},
				DestinationIp:    "5.6.7.8",
				DestinationPort:  &wrapperspb.UInt32Value{Value: 56789},
				DestinationNames: []string{"isovalent.com"},
				Protocol:         fgs.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💡 accept  my-ns/my-pod /usr/bin/nginx TCP 5.6.7.8:56789 => 1.2.3.4:80 [isovalent.com]", result)
}

func TestCompactEncoder_ListenEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessListen{
			ProcessListen: &fgs.ProcessListen{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port field is nil
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessListen{
			ProcessListen: &fgs.ProcessListen{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
				},
				Ip:       "0.0.0.0",
				Protocol: fgs.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🎧 listen  my-node /usr/bin/nginx TCP 0.0.0.0:0", result)

	// with pod info
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessListen{
			ProcessListen: &fgs.ProcessListen{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &fgs.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				Ip:       "0.0.0.0",
				Port:     &wrapperspb.UInt32Value{Value: 80},
				Protocol: fgs.SocketProtocol_TCP,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🎧 listen  my-ns/my-pod /usr/bin/nginx TCP 0.0.0.0:80", result)
}

func TestCompactEncoder_CloseEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessClose{
			ProcessClose: &fgs.ProcessClose{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if port field is nil
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessClose{
			ProcessClose: &fgs.ProcessClose{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
				},
				SourceIp:      "1.2.3.4",
				DestinationIp: "5.6.7.8",
				Stats:         nil,
				Protocol:      fgs.SocketProtocol_TCP,
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "\U0001F9F9 close   my-node /usr/bin/nginx TCP 1.2.3.4:0 => 5.6.7.8:0 tx  rx ", result)

	// with pod info
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessClose{
			ProcessClose: &fgs.ProcessClose{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
					Pod:    &fgs.Pod{Namespace: "my-ns", Name: "my-pod"},
				},
				SourceIp:        "1.2.3.4",
				SourcePort:      &wrapperspb.UInt32Value{Value: 56789},
				DestinationIp:   "5.6.7.8",
				DestinationPort: &wrapperspb.UInt32Value{Value: 80},
				Protocol:        fgs.SocketProtocol_TCP,
				Stats: &fgs.SocketStats{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &fgs.ProcessSockStats{},
		},
	})
	assert.Error(t, err)

	// should fail if socket field is nil
	_, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &fgs.ProcessSockStats{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// should fail if stats field is nil
	_, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &fgs.ProcessSockStats{
				Process: &fgs.Process{
					Binary: "/usr/bin/nginx",
				},
				Socket: &fgs.SockInfo{},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// with socket and stats fields
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessSockStats{
			ProcessSockStats: &fgs.ProcessSockStats{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Socket: &fgs.SockInfo{
					SourceIp:        "1.2.3.4",
					SourcePort:      &wrapperspb.UInt32Value{Value: 56789},
					DestinationIp:   "5.6.7.8",
					DestinationPort: &wrapperspb.UInt32Value{Value: 80},
					Protocol:        fgs.SocketProtocol_TCP,
				},
				Stats: &fgs.SocketStats{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{},
		},
	})
	assert.Error(t, err)

	// should fail if dns field is nil
	_, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// with dns info.
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Dns: &fgs.DnsInfo{
					Names: []string{"isovalent.com"},
					Ips:   []string{"1.2.3.4"},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📖 dns     my-node /usr/bin/curl [isovalent.com] => [1.2.3.4]", result)
}

func TestCompactEncoder_TlsEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_Tls{
			Tls: &fgs.Tls{},
		},
	})
	assert.Error(t, err)

	// shouldn't crash if destination port is nil
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_Tls{
			Tls: &fgs.Tls{
				Process: &fgs.Process{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_Tls{
			Tls: &fgs.Tls{
				Process: &fgs.Process{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessHttp{
			ProcessHttp: &fgs.ProcessHttp{},
		},
	})
	assert.Error(t, err)

	// should fail if http is nil
	_, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessHttp{
			ProcessHttp: &fgs.ProcessHttp{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// http request
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessHttp{
			ProcessHttp: &fgs.ProcessHttp{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &fgs.HttpInfo{
					Request: &fgs.HttpRequest{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessHttp{
			ProcessHttp: &fgs.ProcessHttp{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &fgs.HttpInfo{
					Request: &fgs.HttpRequest{
						Method:  "GET",
						Uri:     "/index.html",
						Version: "1.1",
						Host:    "isovalent.com",
					},
					Response: &fgs.HttpResponse{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessHttp{
			ProcessHttp: &fgs.ProcessHttp{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Http: &fgs.HttpInfo{
					Request: &fgs.HttpRequest{
						Method:  "GET",
						Uri:     "/index.html",
						Version: "1.1",
						Host:    "isovalent.com",
					},
					Response: &fgs.HttpResponse{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{},
		},
	})
	assert.Error(t, err)

	// with status
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail without process field
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.Error(t, err)

	// unknown function
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// open without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "fd_install",
				Args: []*fgs.KprobeArgument{
					nil,
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeWriteEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// write without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_write",
				Args: []*fgs.KprobeArgument{
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
					nil,
					{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 1234}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/hubble-enterprise /usr/bin/curl /etc/password 1234 bytes", result)
}

func TestCompactEncoder_KprobeCloseEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// open without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
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
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_close",
				Args: []*fgs.KprobeArgument{
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_Encode(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&fgs.GetEventsResponse{})
	assert.Error(t, err)

	// valid event
	err = p.Encode(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
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
	p := NewCompactEncoder(os.Stdout, Never)

	// open without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_InterfaceStats{
			InterfaceStats: &fgs.InterfaceStats{
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
