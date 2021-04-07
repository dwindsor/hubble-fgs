package main

import (
	"fmt"
	"os"

	"github.com/covalentio/hubble-fgs/api/v1/fgs"
	"github.com/covalentio/hubble-fgs/pkg/observer"
	"github.com/golang/protobuf/ptypes/wrappers"
)

var (
	jobsTrace = []*fgs.GetEventsResponse{
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{
					Process: &fgs.Process{Binary: "/usr/local/bin/node",
						Arguments: "server.js"},
					Parent: &fgs.Process{Binary: ""},
				},
			},
		},
		&fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessConnect{
				ProcessConnect: &fgs.ProcessConnect{
					Process: &fgs.Process{
						Binary:    "/usr/local/bin/node",
						Arguments: "server.js"},
					Parent:          &fgs.Process{Binary: ""},
					DestinationPort: &wrappers.UInt32Value{Value: 9080},
				},
			},
		},
	}
)

func main() {
	jsonFile, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Printf("🔥 Failed: could not open %s\n", os.Args[1])
		os.Exit(1)
	}
	defer jsonFile.Close()

	if ok := observer.JsonTestCompare(jobsTrace, jsonFile, 1, 0); !ok {
		fmt.Printf("🔥 Failed: no dice\n")
		os.Exit(1)
	}
	fmt.Printf("🚢 Passed: ship it\n")
	os.Exit(0)
}
