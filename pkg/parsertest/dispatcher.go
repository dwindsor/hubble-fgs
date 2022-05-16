package parsertest

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/isovalent/hubble-fgs/pkg/bpf"
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
	log        logrus.FieldLogger
	nextSubId  int
	subs       map[int]*EventSubscription
	perfReader *perf.Reader
}

func NewEventDispatcher() (*EventDispatcher, error) {
	log := logger.GetLogger()
	cfg := bpf.DefaultPerfEventConfig()
	pinOpts := ebpf.LoadPinOptions{}

	perfMap, err := ebpf.LoadPinnedMap(cfg.MapName, &pinOpts)
	if err != nil {
		log.Errorf("ebpf.LoadPinnedMap error: %s", err)
		return nil, err
	}

	perfReader, err := perf.NewReader(perfMap, 65536)
	if err != nil {
		log.Errorf("perf.NewReader error: %s", err)
		return nil, err
	}

	return &EventDispatcher{
		log:        log,
		perfReader: perfReader,
	}, nil
}

func (ed *EventDispatcher) Close() error {
	ed.Lock()
	defer ed.Unlock()

	for _, sub := range ed.subs {
		close(sub.Events)
	}
	ed.subs = nil
	return ed.perfReader.Close()
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

func (ed *EventDispatcher) Run(ctx context.Context, ready chan bool) {
	defer ed.UnsubscribeAll()
	ready <- true
	done := ctx.Done()

	for ctx.Err() == nil {
		record, err := ed.perfReader.Read()
		if err != nil {
			if ctx.Err() == nil {
				ed.log.Errorf("perf.Read failed: %s", err)
			}
			return
		}

		if len(record.RawSample) > 0 {
			op := record.RawSample[0]
			ed.Lock()
			for _, sub := range ed.subs {
				if sub.Op == op {
					select {
					case sub.Events <- record.RawSample:
					case <-done:
						ed.Unlock()
						return
					}
				}
			}
			ed.Unlock()
		}
	}
}
