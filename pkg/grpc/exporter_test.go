package grpc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/api"
	"github.com/stretchr/testify/assert"
)

type arrayWriter struct {
	items []string
	done  chan bool
}

func newArrayWriter(size int) *arrayWriter {
	return &arrayWriter{
		items: make([]string, 0, size),
		done:  make(chan bool),
	}
}

func (a *arrayWriter) Write(p []byte) (n int, err error) {
	a.items = append(a.items, strings.TrimSpace(string(p)))
	if len(a.items) == cap(a.items) {
		a.done <- true
	}
	return len(p), nil
}

type fakeNotifier struct {
	mux       sync.Mutex
	listeners map[listener]struct{}
	added     chan bool
	removed   chan bool
}

func newFakeNotifier() *fakeNotifier {
	return &fakeNotifier{
		listeners: make(map[listener]struct{}),
		added:     make(chan bool),
		removed:   make(chan bool),
	}
}

func (f *fakeNotifier) addListener(listener listener) {
	f.mux.Lock()
	f.listeners[listener] = struct{}{}
	f.added <- true
	f.mux.Unlock()
}

func (f *fakeNotifier) removeListener(listener listener) {
	f.mux.Lock()
	delete(f.listeners, listener)
	f.removed <- true
	f.mux.Unlock()
}

func (f *fakeNotifier) notifyListeners(event *fgs.GetEventsResponse) {
	f.mux.Lock()
	for l := range f.listeners {
		l.notify(event)
	}
	f.mux.Unlock()
}

type fakeObserver struct{}

func (f *fakeObserver) ListSensors(ctx context.Context) (*[]api.SensorStatus, error) {
	return nil, nil
}

func (f *fakeObserver) EnableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *fakeObserver) DisableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *fakeObserver) GetSensorConfig(ctx context.Context, k string, v string) (string, error) {
	return "", nil
}

func (f *fakeObserver) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	return nil
}

func (f *fakeObserver) GetTreeProto(ctx context.Context, tname string) (*fgs.StackTraceNode, error) {
	return nil, nil
}

func (f *fakeObserver) AddTracingPolicy(ctx context.Context, sensorName string, policyYaml string) error {
	return nil
}
func (f *fakeObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func TestExporter_Send(t *testing.T) {
	eventNotifier := newFakeNotifier()
	grpcServer := NewServer(eventNotifier, &fakeObserver{})
	numRecords := 2
	results := newArrayWriter(numRecords)
	encoder := json.NewEncoder(results)
	ctx, cancel := context.WithCancel(context.Background())
	request := fgs.GetEventsRequest{DenyList: []*fgs.Filter{{BinaryRegex: []string{"b"}}}}
	exporter := NewExporter(ctx, &request, grpcServer, encoder)
	go exporter.Start()
	<-eventNotifier.added
	eventNotifier.notifyListeners(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessConnect{
			ProcessConnect: &fgs.ProcessConnect{Process: &fgs.Process{Binary: "a"}},
		}})
	eventNotifier.notifyListeners(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Binary: "b"}},
		}})
	eventNotifier.notifyListeners(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessListen{
			ProcessListen: &fgs.ProcessListen{Process: &fgs.Process{Binary: "c"}},
		}})
	<-results.done
	assert.Equal(t, []string{`{"process_connect":{"process":{"binary":"a"}}}`, `{"process_listen":{"process":{"binary":"c"}}}`}, results.items)
	cancel()
	<-eventNotifier.removed
}
