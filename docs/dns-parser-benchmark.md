_This is copied from https://github.com/isovalent/hubble-fgs/issues/7176._

## Initial request

In dogfooding we see a few hundreds packet per seconds, we would need to stress
test it to a few thousands or a few dozen thousands packet per seconds and see
what happens for customers.

## tl;dr

The BPF DNS parser should be able to withstand any load as long as the kernel
follows (it's a ~10K insns BPF prog), and all the programs from Tetragon
(including the parser) for the application model to run should generate minimal
overhead (in the order of magnitude of µs in our tests, around 5%, for UDP DNS
average latency).

Limitations are that the benchmarks are all performed locally with the load
generator and the server running on the same machine. The first benchmark is
very artificial but allowed us to reach 100K reqs per seconds and measure
latency introduced by our progs with more precision. The second benchmark is
more realistic but didn't allow us to have stats but helped us enhance/fix the
parser:
- https://github.com/isovalent/hubble-fgs/pull/7296
- https://github.com/isovalent/hubble-fgs/pull/7316

The testing setup is limited in many ways and results should be taken with
caution, they might differ from real customer use case.

## Protocol

For the machine I'll use a `c2-standard-30 (30 vCPU, 120 GB of memory)` from
Google cloud running `6.8.0-1043-gcp`.

Starting bind9 in forward mode locally.
```shell
sudo named -g -d 1
```

Then I start Tetragon with the minimal stuff I need:
- the DNS parser,
- the application model,
- the metrics server to retrieve stats from the DNS parser,
- and I increase the max pending requests since we are going to send a lot of
  simultaneous queries (see [docs on that option for
  details](https://docs.isovalent.com/v25.11/tetragon/bpf-dns-parser/index.html#maximum-pending-requests)).

```shell
sudo ./tetragon --bpf-lib bpf/objs/ --enable-bpf-dns-parser --enable-udp --metrics-server :2112 --enable-application-model --bpf-dns-parser-max-pending-requests 10000
```

Then on the side I watch the non NULL metrics from the parser
```shell
watch -n1 'curl -s localhost:2112/metrics | grep dns_parser | grep -v " 0$"'
```

Then to generate a high load of DNS queries, I use
[dnsperf(1)](https://github.com/DNSPerf/dnsperf), also [more info
here](https://www.dns-oarc.net/tools/dnsperf). We will mostly use those
options:
- `-s 127.0.0.1` - query our local bind9 instance
- `-d file` - run queries based on the content of file
- `-l <seconds>` - run the test for given seconds, otherwise it just reads the
  query file one time and finishes
- `-Q <max_qps>` - limits the number of requests per second.
- `-c <clients>` - act as multiple clients/sockets.

> [!WARNING]
> This protocol has limitations since all the queries are going through
> localhost and the process generating the load is running on the same host as
> the process taking the load (bind9 and tetragon). Also first dnsperf pass
> will make bind9 cache most of the entries, second pass might be more
> representative of local traffic.

## First benchmark

### Setup

For the first benchmark, we are using a limited number of domains that we are
going to loop over to generated enough traffic. Quite fast, we are going to
operate with bind9 having all the information cached locally.

The first files contains 100 domains of well-known internet services chosen
arbitrarily. Here's an extract:
```
google.com A
google.com AAAA
youtube.com A
youtube.com AAAA
facebook.com A
facebook.com AAAA
twitter.com A
twitter.com AAAA
instagram.com A
instagram.com AAAA
```

For each of these domains we have two entries, with A and AAAA queries so the
file contains 200 queries.

### 1 client, 1000 queries per second during 1 minute

We observe different output given the cache of bind9 has already been populated
or freshly started. For this test will pre-populate with a full-run of the
queries first then to be able to compare the results.

#### No prior caching

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d queries100.txt -l 60 -Q 1000
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 16:29:33 2025
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         60000
  Queries completed:    60000 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 59976 (99.96%), SERVFAIL 24 (0.04%)
  Average packet size:  request 29, response 83
  Run time (s):         60.000082
  Queries per second:   999.998633

  Average Latency (s):  0.000251 (min 0.000026, max 0.588757)
  Latency StdDev (s):   0.006153
```

#### With prior caching

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d queries100.txt -l 60 -Q 1000
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 16:31:27 2025
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         60000
  Queries completed:    60000 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 60000 (100.00%)
  Average packet size:  request 29, response 83
  Run time (s):         60.000081
  Queries per second:   999.998650

  Average Latency (s):  0.000039 (min 0.000026, max 0.009896)
  Latency StdDev (s):   0.000198
```

You can see that the server needs to do actual DNS request through the network
without prior caching so the max latency is half a second in first case.
```
Without cache filled
  Average Latency (s):  0.000251 (min 0.000026, max 0.588757)
  Latency StdDev (s):   0.006153

With cache filled
  Average Latency (s):  0.000039 (min 0.000026, max 0.009896)
  Latency StdDev (s):   0.000198
```

### 1,000 client, 100,000 queries per second during 10 seconds

Let's generate a bit more load, since most of it is local and hitting the
cache, it's generating very little load on bind9. In this case 1000 clients are
doing each 1000 queries per seconds, so 100,000 queries per seconds during 10
seconds (thus 1M queries).

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d queries100.txt -l 10 -Q 100000 -c 1000
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 16:45:17 2025
[Status] Stopping after 10.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         999998
  Queries completed:    999998 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 999998 (100.00%)
  Average packet size:  request 28, response 83
  Run time (s):         10.000113
  Queries per second:   99998.670015

  Average Latency (s):  0.000091 (min 0.000017, max 0.008780)
  Latency StdDev (s):   0.000046
```

Now we can do something interesting to see how much Tetragon introduce overall
latency in this use case by stopping Tetragon and running the same load on the
system.

> [!IMPORTANT]
> Tetragon hooks into process exec/exit on top of network hooks for the DNS
> parsing and other features needed for the application model to be populated.
> Keep in mind that generating the load is also putting very high pressure on
> the system and here we account for both the load from the clients generating
> and the server receiving the load. So this might not be representative of a
> real use case.

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d queries100.txt -l 10 -Q 100000 -c 1000
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 16:47:47 2025
[Status] Stopping after 10.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         999994
  Queries completed:    999994 (100.00%)
  Queries lost:         0 (0.00%)

  Response codes:       NOERROR 999994 (100.00%)
  Average packet size:  request 28, response 83
  Run time (s):         10.000015
  Queries per second:   99999.250001

  Average Latency (s):  0.000086 (min 0.000015, max 0.008267)
  Latency StdDev (s):   0.000049
```

We can see in average that Tetragon introduces around 5 µs, the latency jumps
from 0.000086s to 0.000091s in average. So it's roughly around 5% of latency
introduced.

Keep in mind that it might be more than actual latency because we also slow
down the system by generating the load. Also the way we test, with the
arguments chosen (number of client, duration of the test, throughput) might
alter the results.

This is a very artificial load but it helps us exercise the codepaths in which
the parser and most of Tetragon programs are called in the kernel like an
actual large DNS server might stress them. So even thought the general latency
is low because everything is cached and local, the throughput is high.

Checking the metrics, you should see that almost 100% of the packets have been
successfully parsed by the DNS parser. Search for
`tetragon_dns_parser_error_total{error_name="DNS_ERR_SUCCESS",error_number="0"}`.

## Second benchmark

### Setup

Let's use more realistic queries list, for that we can use
https://radar.cloudflare.com/domains that can provide the top up to the top
1,000,000 domains. Let's start with the top 10,000 domains and double it with A
and AAAA queries, so 20,000 queries from the top 10,000 domains.

Here's an extract
```
partnerlinks.io A
partnerlinks.io AAAA
partners-show.com A
partners-show.com AAAA
passfixx.com A
passfixx.com AAAA
passport.net A
passport.net AAAA
pastebin.com A
pastebin.com AAAA
patch.com A
patch.com AAAA
patreon.com A
patreon.com AAAA
patreonusercontent.com A
patreonusercontent.com AAAA
pavv.co.kr A
pavv.co.kr AAAA
pawns.app A
pawns.app AAAA
pawwalls.com A
pawwalls.com AAAA
```

> [!CAUTION]
> I realized in the process that this list contains any domain, malicious or
> not, and safe for work or not (or maybe worse) per Cloudflare warning: "Note
> that the top 100 domains and trending domains lists include domains with
> organic activity as well as domains with emerging malicious behavior.". Which
> might be even worse in the top 1M domains.

### 1 client, 20,000 queries to do

On a fresh start, we obtain something like ~1000 queries per second, a run time
of a couple dozens of seconds which doesn't scale by increasing the number of
clients.

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d cloudflare_top_10000_AAAA.txt
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 17:30:04 2025
[Status] Stopping after 1 run through file
[Timeout] Query timed out: msg id 602
[Timeout] Query timed out: msg id 603
Warning: received a response with an unexpected (maybe timed out) id: 602
Warning: received a response with an unexpected (maybe timed out) id: 603
[...]
Warning: received a response with an unexpected (maybe timed out) id: 14055
[Timeout] Query timed out: msg id 16688
[Timeout] Query timed out: msg id 16689
[Timeout] Query timed out: msg id 16822
[Timeout] Query timed out: msg id 16823
[Status] Testing complete (end of file)

Statistics:

  Queries sent:         20000
  Queries completed:    19945 (99.72%)
  Queries lost:         55 (0.28%)

  Response codes:       NOERROR 19911 (99.83%), SERVFAIL 21 (0.11%), NXDOMAIN 13 (0.07%)
  Average packet size:  request 30, response 91
  Run time (s):         19.913360
  Queries per second:   1001.588883

  Average Latency (s):  0.078347 (min 0.000394, max 4.823092)
  Latency StdDev (s):   0.215703
```

Running the same experiment now that the server has cached some entries, it's
faster, and we can scale a little bit by increasing the number of clients.

```
DNS Performance Testing Tool
Version 2.9.0

[Status] Command line: dnsperf -s 127.0.0.1 -d cloudflare_top_10000_AAAA.txt
[Status] Sending queries (to 127.0.0.1:53)
[Status] Started at: Thu Nov 27 17:30:35 2025
[Status] Stopping after 1 run through file
[Timeout] Query timed out: msg id 602
[Timeout] Query timed out: msg id 603
[Timeout] Query timed out: msg id 2136
[...]
[Timeout] Query timed out: msg id 19597
[Status] Testing complete (end of file)

Statistics:

  Queries sent:         20000
  Queries completed:    19940 (99.70%)
  Queries lost:         60 (0.30%)

  Response codes:       NOERROR 19916 (99.88%), SERVFAIL 10 (0.05%), NXDOMAIN 14 (0.07%)
  Average packet size:  request 30, response 91
  Run time (s):         4.931287
  Queries per second:   4043.569153

  Average Latency (s):  0.002080 (min 0.000019, max 4.800265)
  Latency StdDev (s):   0.047862
```

While testing a lot more of real life domains helped fixing bugs[^1] in the parsers:
- https://github.com/isovalent/hubble-fgs/pull/7296
- https://github.com/isovalent/hubble-fgs/pull/7316

It's almost impossible to draw any conclusion on latency introduced by all
Tetragon sensors on these with our protocol here because the average latency
and throughput is too high compared to the estimated introduced latency and the
measures are not stable enough between tests.

[^1]: Note that since the BPF parser is verified, bugs can only lead to
situations in which the parsers evaluates the packet as malformed and fails to
parse it. Also note that in the real life testing, some packets were also
marked as malformed by Wireshark during analysis, so errors from the parser
might signify that packets are genuinely not following the RFC and are
malformed.

## Conclusion

From the testing above, we can conclude that Tetragon enabled with the
application model and the DNS parser should be capable to withstand very large
UDP DNS load (we tested with at least 100K queries per second).

The DNS parser in itself is a short program, in the order of magnitude of
10,000 BPF instructions (~16000 insns with the BPF unit test harness) and even
if we noted around 5 µs of average latency introduced in our specific setup,
the impact of the DNS parser in that should be small and could be actually
measured if we isolate that program instead of bundling it within the layer3
and running it along all the other Tetragon sensors.

Note that we propose a Grafana dashboard to interpret the metrics coming from
the DNS parser to gather statistics on throughput, observe our success rate in
parsing and see some details on errors:
- https://github.com/isovalent/hubble-fgs/issues/5615.
