// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package parsertest

import (
	"context"
	"sync"

	"github.com/cilium/tetragon/pkg/constants"
	"github.com/sirupsen/logrus"
)

type EventDispatcher struct {
	sync.Mutex
	log        logrus.FieldLogger
	nextSubId  int
	subs       map[int]*EventSubscription
	perfReader uint32
}

func NewEventDispatcher() (*EventDispatcher, error) {
	return nil, constants.ErrWindowsNotSupported
}

func (ed *EventDispatcher) Close() error {
	return constants.ErrWindowsNotSupported
}

func (ed *EventDispatcher) Run(ctx context.Context, ready chan bool) {

}
