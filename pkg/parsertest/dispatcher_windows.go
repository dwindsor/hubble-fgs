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
