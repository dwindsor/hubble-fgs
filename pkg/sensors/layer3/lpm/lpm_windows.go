package lpm

import (
	"errors"

	"github.com/cilium/tetragon/pkg/bpf"
)

func NewLPM() (LPMMap, error) {
	coll, err := bpf.GetCollection("tcp_connect4")
	if coll == nil {
		return nil, errors.New("tcp preload collection is nil")
	}
	addr4lpm := coll.Maps[Addr4lpmMapName]
	if addr4lpm == nil {
		return nil, errors.New("failed to load addr4 LPM Map from collection")
	}
	addr6lpm := coll.Maps[Addr6lpmMapName]
	if err != nil {
		return nil, errors.New("failed to load addr6 LPM Map from collection")
	}

	return &lpmMapImpl{
		addr6: addr6lpm,
		addr4: addr4lpm,
	}, nil
}
