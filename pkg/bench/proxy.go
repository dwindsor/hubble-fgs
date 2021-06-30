// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package bench

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"
	"text/template"
)

type Proxy interface {
	Start(ctx context.Context, sinkPort int) (int, chan ProxyStats, error)
}

type ProxyStats struct {
	CPUUsage CPUUsage
}

type proxyName string

var (
	proxies = map[proxyName]Proxy{
		"none":  noneProxy{},
		"envoy": envoyProxy{},
	}
)

func ProxyNameOrPanic(s string) proxyName {
	if _, ok := proxies[proxyName(s)]; ok {
		return proxyName(s)
	} else {
		log.Fatalf("Unknown proxy '%s', use on of: %s", s, strings.Join(SupportedSources(), ", "))
		return proxyName("")
	}
}

func SupportedProxies() []string {
	keys := make([]string, 0, len(proxies))
	for k := range proxies {
		keys = append(keys, string(k))
	}
	return keys
}

//
// None
//

type noneProxy struct{}

func (np noneProxy) Start(ctx context.Context, sinkPort int) (int, chan ProxyStats, error) {
	return sinkPort, nil, nil
}

//
// Envoy proxy
//

type envoyProxy struct{}

const envoyConfigTemplate = `
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 127.0.0.1
        port_value: {{.EnvoyPort}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          access_log:
          - name: envoy.access_loggers.stdout
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
          http_filters:
          - name: envoy.filters.http.router
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: service_localhost

  clusters:
  - name: service_localhost
    load_assignment:
      cluster_name: service_localhost
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: {{.SinkPort}}
`

func (ep envoyProxy) Start(ctx context.Context, sinkPort int) (int, chan ProxyStats, error) {
	tmpl := template.Must(template.New("envoy-template").Parse(envoyConfigTemplate))
	f, err := ioutil.TempFile("/tmp", "fgs-bench-envoy-*.yaml")
	if err != nil {
		return -1, nil, fmt.Errorf("failed to open temporary file: %w", err)
	}
	f.Chmod(0644)

	// FIXME try to find a free port
	envoyPort := 8989
	err = tmpl.Execute(f, struct{ EnvoyPort, SinkPort int }{EnvoyPort: envoyPort, SinkPort: sinkPort})
	if err != nil {
		return -1, nil, fmt.Errorf("failed to generate envoy config: %w", err)
	}
	f.Sync()

	cmd := exec.Command(
		"docker", "run", "--rm",
		"--detach",
		"--network=host",
		"--name=fgs-bench-envoy",
		"--volume=/tmp:/tmp",
		"envoyproxy/envoy:v1.19.0",
		"--config-path",
		f.Name())

	out, err := cmd.Output()
	if err != nil {
		return -1, nil, fmt.Errorf("failed to start envoy: %w", err)
	}
	containerID := strings.TrimSpace(string(out))

	if !ProbeTCPPort(envoyPort) {
		exec.Command("docker", "stop", "fgs-bench-envoy").Run()
		f.Close()
		return -1, nil, fmt.Errorf("envoy did not start up on time")
	}

	statsCh := make(chan ProxyStats, 1)
	go func() {
		<-ctx.Done()
		cpuUsage := CPUUsageFromCPUAcct(containerID)
		exec.Command("docker", "stop", "fgs-bench-envoy").Run()
		f.Close()
		statsCh <- ProxyStats{cpuUsage}
	}()
	return envoyPort, statsCh, nil

}
