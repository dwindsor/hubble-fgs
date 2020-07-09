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
	"context"
	"net"

	"github.com/covalentio/hubble-fgs/pkg/logger"
	"github.com/covalentio/hubble-fgs/pkg/observer"
)

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// ServeEvents accepts connections and adds them to ObserverKprobe. Note that this function blocks
// on net.Listener.Accept() call. It's up to the caller to make this function return by cancelling
// the context and then closing the net.Listener so that net.Listener.Accept() returns.
func ServeEvents(k *observer.ObserverKprobe, ctx context.Context, listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if isCtxDone(ctx) {
			return
		} else if err != nil {
			logger.GetLogger().WithError(err).Warn("Accept failed")
			continue
		}
		k.AddListener(observer.NewObserverChannel(conn))
	}
}
