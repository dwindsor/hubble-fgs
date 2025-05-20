package parsertest

import (
	"context"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
)

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
