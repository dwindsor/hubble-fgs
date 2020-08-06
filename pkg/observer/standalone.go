// Copyright 2020 Authors of Hubble
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

package observer

import (
	"context"
	"fmt"

	"github.com/covalentio/hubble-fgs/pkg/logger"
)

type standaloneListener struct {
}

func (sl *standaloneListener) Notify(msg interface{}) error {
	_, err := fmt.Printf("=> %v\n", msg)
	return err
}

func (sl *standaloneListener) Close() error {
	return nil
}

func (k *ObserverKprobe) StartStandalone(ctx context.Context) error {
	if len(k.listeners) > 0 {
		return fmt.Errorf("hubble-fgs, Cowardly refusing to start in standalone mode with other listeners registered\n")
	}
	logger.GetLogger().Info("starting observer in standalone mode")
	k.AddListener(&standaloneListener{})
	return k.Start(ctx)
}
