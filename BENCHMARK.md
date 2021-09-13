# Introduction

fgs-bench is a tool to run various benchmarks alongside FGS and
report the data such as rate per second (request or connection),
the BPF program average runtimes and CPU usage of the different
processes.

Conceptually the tool launches 4 different processes:
- FGS (unless run with -baseline)
- Source (a connection or request source, e.g. netperf-rr)
- Sink (a sink, e.g. netperf or http-nginx)
- Proxy (currently only envoy is supported)

The currently supported sources are:
- netperf-rr, netperf-crr: netperf TCP (connect)-request-response
- tls-crr, tls-rr: Go TLS (connect)-request-response
- http-rr-h2load: h2load HTTP/1.1 request-response
- http2-rr-h2load: h2load HTTP/2 request-response
- tcp-crr, tcp-rr: TCP (connect)-request-response
- http-rr-go, http-crr-go: Go HTTP (connect)-request-response

The difference between CRR and RR tests is that CRR opens a separate
connection for each request, while the RR test reuses a connection.

The supported sinks are:
- tcp-go: TCP server written in Go (net)
- tls-go: TLS server written in Go (crypto/tls)
- http-go: HTTP server written in Go (net/http)
- http-nginx: Nginx run via Docker
- netperf: Locally installed netperf

# Compiling and running the fgs-bench to measure FGS performance:

$ git clone git@github.com:isovalent/hubble-fgs
$ cd hubble-fgs
$ make tools-install # get clang and libbpf
$ PATH=$PWD/bin make bpf
$ make fgs-bench
$ sudo LD_LIBRARY_PATH=$PWD/lib ./fgs-bench -h
Usage of ./fgs-bench:
...

To use fgs-bench you'll need to decide:
- The source and sink, e.g. -source=http-rr-go -sink=http-nginx
- FGS parsers, if any, e.g. -parsers=http,tls
- The test duration, e.g. -duration=5s
- The RR/CRR rate, e.g. -rate=100 (100 per second)

Note that some source/sink combinations may require locally installed
applications (netperf for now) or require that Docker is present.

An example run could look like:

    $ sudo LD_LIBRARY_PATH=$PWD/lib ./fgs-bench -source=http-rr-go -sink=http-nginx -duration=5s -rate=100
    2021/09/13 17:42:29 Starting sink 'http-nginx'...
    2021/09/13 17:42:30 Starting FGS...
    ...
    2021/09/13 17:42:31 Starting proxy 'none'...
    2021/09/13 17:42:31 Starting source 'http-rr-go'...
    2021/09/13 17:42:36 Benchmark finished: 100.96 per sec, 0 error(s)
    Benchmark summary
    -----------------
    Started:           2021-09-13 17:42:29.7300026 +0200 CEST m=+0.031706845
    Ended:             2021-09-13 17:42:36.300130969 +0200 CEST m=+6.601835218
    Arguments:         sink=http-nginx, source=http-rr-go, proxy=none, source-args={duration=5s, rate=100.00, req-size=64}, fgs-tls=false, json-encode=false
    Total duration:    6.570128373s
    Setup duration:    1.559445931s
    Test duration:     6.570128373s
    Export duration:   0s
    FGS cpu usage:     system=1.03083s, user=697.629ms, rss=98816
    Source cpu usage:  system=116.42ms, user=68.264ms, rss=98780
    Proxy cpu usage:   system=0s, user=0s, rss=0
    Sink cpu usage:    system=200ms, user=80ms, rss=5406720
    Actual rate:       100.96 per second
    Latency 50th:      923.909µs
    Latency 90th:      1.075137ms
    Latency 99th:      1.213854ms
    Events:            tls=0, http=0, tcp=37, exit=259, exec=410
    BPF statistics:
      event_exit       [tracepoint/184]:	6.667µs
      event_execve     [tracepoint/182]:	19.891µs
      event_wake_up_n  [kprobe/186]:	2.399µs
      event_ipv4_conn  [kprobe/191]:	9.841µs
      event_tcp_v4_se  [kprobe/199]:	1.354µs
      event_ret_ipv4_  [kprobe/193]:	468ns
      event_commit_cr  [kprobe/188]:	1.369µs
      event_ipv4_clos  [kprobe/196]:	1.656µs

Few explanations for the lines you see above:
- Setup duration measures the time it takes for FGS to become ready to process events
- CPU usage is the "rusage" measure of how much kernel and user-space CPU time was spent
  on this component. "rss" is the maximum resident set size, e.g. the maximum amount of
  real (non-swapped) pages the process has held.
- Actual rate is the reported rate from the source.
- Latency 50th/90th/99th: latency percentiles as reported by the source. Not all sources support it.
- Events reports the count for each event sent by FGS
- BPF statistics is the average BPF runtime for each loaded program
  (as reported by "bpftool prog list").

# Known issues

- Due to Go's concurrent runtime CPU statistics cannot currently be
  reported for the http-go sink.
- HTTP parser still has few known issues with some source/sink combinations
  and localhost connections, so the event counter may not be correct.



