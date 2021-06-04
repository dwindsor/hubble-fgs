package main

import (
	"fmt"
	"os"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/isovalent/hubble-fgs/api/v1/fgs"
	"github.com/isovalent/hubble-fgs/pkg/observer"
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
	ok, err := observer.JsonTestCompare(jobsTrace, os.Args[1], 1, 0)
	if err != nil {
		fmt.Printf("🔥 Failed: no dice: %v\n", err)
		os.Exit(1)
	}
	if !ok {
		fmt.Printf("🔥 Failed: no dice\n")
		os.Exit(1)
	}
	fmt.Printf("🚢 Passed: ship it\n")
	os.Exit(0)
}
