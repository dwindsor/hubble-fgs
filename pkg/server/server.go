// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package server

import (
	"github.com/covalentio/hubble-fgs/pkg/observer"

	"context"
	"fmt"
	"net"
	"os"
)

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func ServeEvents(k *observer.ObserverKprobe, ctx context.Context, path string) (net.Listener, error) {
	os.Remove(path)
	server, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("failed net.Listen: %s: %s\n", path, err)
	}

	for !isCtxDone(ctx) {
		conn, err := server.Accept()
		switch {
		case isCtxDone(ctx) && conn != nil:
			k.RemoveListener(conn)
			conn.Close()
			return nil, fmt.Errorf("ServeEvents ctx close\n")
		case isCtxDone(ctx) && conn == nil:
			k.RemoveListener(conn)
			return nil, fmt.Errorf("ServeEvents nil connection\n")
		case err != nil:
			continue
		}
		if conn != nil {
			k.AddListener(conn)
		}
	}
	return server, nil
}
