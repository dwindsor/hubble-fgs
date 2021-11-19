package parsertest

import (
	"sync"
	"syscall" //nolint
	"time"

	"github.com/isovalent/hubble-fgs/pkg/bpf"
	"github.com/isovalent/hubble-fgs/pkg/logger"
	"github.com/sirupsen/logrus"
)

//
// A minimal "Observer" implementation for figuring out what we need for
// low-level testing. Very likely we can modify Observer to work well here.
// Just need a hook to skip all handlers and process the event directly.
//

type EventSubscription struct {
	Op          byte
	Events      chan []byte
	Unsubscribe func()
}

type EventDispatcher struct {
	sync.Mutex
	log          logrus.FieldLogger
	nextSubId    int
	subs         map[int]*EventSubscription
	perCpuEvents *bpf.PerCpuEvents
}

func NewEventDispatcher() (*EventDispatcher, error) {
	log := logger.GetLogger()
	e, err := bpf.NewPerCpuEvents(bpf.DefaultPerfEventConfig(), log)
	if err != nil {
		return nil, err
	}
	return &EventDispatcher{
		log:          log,
		perCpuEvents: e,
	}, nil
}

func (ed *EventDispatcher) Subscribe(op byte) *EventSubscription {
	ed.Lock()
	defer ed.Unlock()

	id := ed.nextSubId
	ed.nextSubId++
	events := make(chan []byte, 32)

	if ed.subs == nil {
		ed.subs = make(map[int]*EventSubscription)
	}

	sub := &EventSubscription{
		Op:     op,
		Events: events,
		Unsubscribe: func() {
			ed.Lock()
			delete(ed.subs, id)
			ed.Unlock()
		},
	}
	ed.subs[id] = sub

	return sub
}

func (ed *EventDispatcher) UnsubscribeAll() {
	ed.Lock()
	defer ed.Unlock()

	for _, sub := range ed.subs {
		close(sub.Events)
	}
	ed.subs = nil
}

func (ed *EventDispatcher) Run(duration time.Duration, ready, done chan bool) error {
	defer ed.UnsubscribeAll()

	ready <- true

	evRecv := func(msg *bpf.PerfEventSample, cpu int) {
		data := msg.DataDirect()
		op := data[0]
		ed.Lock()
		for _, sub := range ed.subs {
			if sub.Op == op {
				sub.Events <- data
			}
		}
		ed.Unlock()
	}
	evLost := func(msg *bpf.PerfEventLost, cpu int) {
		ed.log.Errorf("Event lost: %v\n", msg)
	}

	var perfEventError error = nil
	evErr := func(msg *bpf.PerfEvent) {
		ed.log.Errorf("PerfEvent error")
	}

	end := time.Now().Add(duration)
	for perfEventError == nil && time.Now().Before(end) {
		select {
		case <-done:
			return nil
		default:
		}

		_, err := ed.perCpuEvents.Poll(100)
		if err != nil {
			if errno, ok := err.(syscall.Errno); ok && errno.Temporary() {
				continue
			}

			ed.log.Errorf("Poll failed: %s", err)
			return err
		}
		if err := ed.perCpuEvents.ReadAll(100, evRecv, evLost, evErr); err != nil {
			return err
		}
	}
	return perfEventError
}
