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
						Arguments: "server.js",
						Pod: &fgs.Pod{
							Namespace: "tenant-jobs",
							Name:      "jobposting",
							Labels: []string{"k8s:app=jobposting",
								"k8s:io.cilium.k8s.policy.cluster=fgs-cli-ci-11",
								"k8s:io.cilium.k8s.policy.serviceaccount=default",
								"k8s:io.kubernetes.pod.namespace=tenant-jobs"},
							Container: &fgs.Container{
								Name: "jobposting",
								Image: &fgs.Image{
									Name: "quay.io/isovalent/jobs-app-jobposting:latest",
								},
							},
						},
					},
					Parent: &fgs.Process{Binary: "/bin/sh",
						Arguments: "-c \"PORT=9080 node server.js\"",
						Pod: &fgs.Pod{
							Namespace: "tenant-jobs",
							Name:      "jobposting",
							Labels: []string{"k8s:app=jobposting",
								"k8s:io.cilium.k8s.policy.cluster=fgs-cli-ci-11",
								"k8s:io.cilium.k8s.policy.serviceaccount=default",
								"k8s:io.kubernetes.pod.namespace=tenant-jobs"},
							Container: &fgs.Container{
								Name: "jobposting",
								Image: &fgs.Image{
									Name: "quay.io/isovalent/jobs-app-jobposting:latest",
								},
							},
						},
					},
					Ancestors: []*fgs.Process{
						&fgs.Process{
							Binary:    "/usr/local/bin/docker-entrypoint.sh",
							Arguments: "/usr/local/bin/docker-entrypoint.sh /bin/sh -c \"PORT=9080 node server.js\"",
							Pod: &fgs.Pod{
								Namespace: "tenant-jobs",
								Name:      "jobposting",
								Labels: []string{"k8s:app=jobposting",
									"k8s:io.cilium.k8s.policy.cluster=fgs-cli-ci-11",
									"k8s:io.cilium.k8s.policy.serviceaccount=default",
									"k8s:io.kubernetes.pod.namespace=tenant-jobs"},
								Container: &fgs.Container{
									Name: "jobposting",
									Image: &fgs.Image{
										Name: "quay.io/isovalent/jobs-app-jobposting:latest",
									},
								},
							},
						},
						&fgs.Process{
							Binary:    "/usr/bin/containerd-shim",
							Arguments: "-namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/",
						},
					},
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
