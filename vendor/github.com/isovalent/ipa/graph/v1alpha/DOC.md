# Graph API documentation and overall concepts

## Overview

The graph API is a protobuf based API that enables data sources to export
connection events that a client can query to render arbitrary graphs.

The graph API is the spiritual successor to the Hubble v1 API for using
networking data to draw graph representations of networking concepts. Although
the initial use cases revolve around networking, the API is extensible and
adapts to any kind of connection as new `Edge` and `Vertex` types are added.
This extensibility allows rendering almost arbitrary graphs, as long as the
underlying data is available.

### Relationship to Hubble Flow

The graph API is complementary to the Hubble Flow API. Both APIs serve different
purposes and work together:

#### Comparison table

| Aspect | Hubble Flow API | Graph API (Connection Logs) |
|--------|-----------------|----------------------------|
| **Purpose** | Individual flow observability and troubleshooting | Aggregated graph visualization and analysis |
| **Granularity** | Discrete events at a specific point in time | Time-windowed aggregations of connections between endpoints |
| **Data model** | Rich, detailed `Flow` message tightly coupled to networking concepts found in Cilium (L2/L3/L4/L7 details, verdict, drop reasons, policy matching, trace information) | `Connection` with separate `Vertex` (endpoint properties) and `Edge` (aggregatable telemetry data) |
| **Use cases** | Real-time monitoring, troubleshooting connectivity issues, policy troubleshooting | Service dependency mapping, traffic patterns visualization, capacity planning, network policy coverage analysis, high-level observability |
| **Output** | Stream of individual flow events as they happen | Periodic connection logs with pre-aggregated metrics |
| **Event model** | Individual flow events | Aggregated connection summaries |
| **Timestamp** | Single point in time | Time window (start/end) |
| **Metrics** | Instantaneous values | Aggregated telemetry data |
| **Volume** | High (one event per flow) | Low (one event per vertex pair per window) |
| **Aggregation** | Limited (connection or identity) | Built-in at source and query time |
| **Extensibility** | Fixed schema | Extensible vertex/edge types |

#### Why a new event type?

Connection logs were created to address specific limitations when using Hubble
Flow for graph visualization:

1. **Volume reduction**: Hubble Flow can generate millions of events per second.
   For graph visualization, this needs to be aggregated. The graph API
   aggregates at the source, which reduces the load on the network as well as
   when storing and processing data.

2. **Graph-optimized structure**: Separating vertex properties from edge
   telemetry enables flexible client-side grouping and aggregation without
   re-parsing complex flow structures.

3. **Extensibility**: Developers can add new vertex families and edge types without
   breaking existing clients. Hubble Flow's schema is more tightly coupled to
   networking concepts found in Cilium.

4. **Storage efficiency**: Aggregated connection logs require significantly less
   storage than raw flow events for long-term retention.

#### Using both together

The APIs are complementary:
- Use **Hubble Flow** for real-time troubleshooting, policy verification, and
  detailed flow inspection
- Use **Graph API** for visualizing service maps, analyzing traffic patterns,
  and understanding system topology over time
- Emitters like Hubble can generate both Flow events and Connection logs from
  the same observations

## Core concepts

### Data model

The graph API consists of four main components:

1. **ConnectionLog**: A time-windowed message emitted by a data source
2. **Connection**: A directed graph with source vertex → destination vertex
   linked by edges. The source is the side that *initiated* the connection and
   the destination is the side it was initiated towards, independent of where it
   was observed (see [Connection direction, emitters, and observers](#connection-direction-emitters-and-observers)).
3. **Vertex**: Properties of a connection endpoint (source or destination)
4. **Edge**: Aggregatable telemetry properties of the connection

#### Complete example: Kubernetes pod-to-pod connection

Here's a complete example of a ConnectionLog containing a single connection
between two Kubernetes pods with multiple edge types:

```json5
{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "emitter": {
    "name": "Hubble",
    "version": "1.16.0",
    // observer identifies the entity that actually saw the traffic. For a
    // self-observing agent like Hubble the observer is the same software as
    // the emitter, so only observer.identifier need be set (name/version fall
    // back to the emitter). Use "cluster_name/node_name" for a Cilium agent.
    "observer": {
      "identifier": "prod-us-west/node-us-west-1a"
    }
  },
  "window_start": "2026-03-26T10:00:00Z",
  "window_end": "2026-03-26T10:00:10Z",
  "connections": [{
    "source": {
      "kubernetes": {
        "cluster_name": "prod-us-west",
        "namespace": "frontend",
        "pod_name": "web-server-abc123",
        "resource_kind": "RESOURCE_KIND_WORKLOAD",
        "resource_name": "web-server-abc123",
        "ip": "10.0.1.50",
        "port": 8080,
        "ip_protocol": "IP_PROTOCOL_TCP"
      }
    },
    "destination": {
      "kubernetes": {
        "cluster_name": "prod-us-west",
        "namespace": "backend",
        "pod_name": "api-service-def456",
        "resource_kind": "RESOURCE_KIND_WORKLOAD",
        "resource_name": "api-service-def456",
        "ip": "10.0.2.100",
        "port": 9090,
        "ip_protocol": "IP_PROTOCOL_TCP"
      }
    },
    "links": [
      {
        "network_telemetry": {
          "network_transmit_packets_total": 1250,
          "network_transmit_bytes_total": 523400,
          "network_transmit_drop_total": 0,
          "network_receive_packets_total": 1180,
          "network_receive_bytes_total": 89200
        }
      },
      {
        "l4_telemetry": {
          "tcp_retransmits_total": 3,
          "tcp_zero_window_total": 0,
          "tcp_resets_total": 0
        }
      },
      {
        "l7_telemetry": {
          "http_requests_total": 450,
          "http_server_errors_total": 2,
          "http_client_errors_total": 15
        }
      }
    ]
  }]
}
```

This example shows:
- A 10-second observation window
- Network-level metrics (packets, bytes)
- Transport-level metrics (TCP retransmits)
- Application-level metrics (HTTP requests and errors)

All metrics are aggregated over the time window for this specific
source/destination pair.

#### Example: network device connection

The graph API also supports network devices as vertices:

```json5
{
  "source": {
    "network_device": {
      "name": "switch-01",
      "ip": "192.168.1.1",
      "interface_name": "eth0",
      "vlan_name": "production",
      "vlan_id": 100
    }
  },
  "destination": {
    "network_device": {
      "name": "router-02",
      "ip": "192.168.1.254",
      "interface_name": "eth1",
      "vlan_name": "production",
      "vlan_id": 100
    }
  },
  "links": [{
    "routing_telemetry": {
      "routing_forwarded_total": 125000,
      "routing_dropped_total": 45,
      "routing_dropped_policy_total": 12
    }
  }]
}
```

#### Example: Kubernetes service to external endpoint

Connections can span different vertex families:

```json5
{
  "source": {
    "kubernetes": {
      "cluster_name": "prod-us-west",
      "namespace": "backend",
      "resource_kind": "RESOURCE_KIND_SERVICE",
      "resource_name": "api-gateway",
      "service_kind": "SERVICE_KIND_CLUSTER_IP",
      "ip": "10.96.0.50",
      "port": 443,
      "ip_protocol": "IP_PROTOCOL_TCP"
    }
  },
  "destination": {
    "world_entity": {
      "dns_name": "api.external-service.com",
      "ip": "203.0.113.45",
      "port": 443,
      "ip_protocol": "IP_PROTOCOL_TCP"
    }
  },
  "links": [{
    "l7_telemetry": {
      "http_requests_total": 89,
      "http_server_errors_total": 0,
      "http_client_errors_total": 4
    }
  }]
}
```

### Connection direction, emitters, and observers

Three distinct concepts come together here, and it is important not to conflate
them:

- The **emitter** is the entity that produces a `ConnectionLog` message. It is
  identified by `emitter.name` and `emitter.version`.
- The **observer** is the entity that actually saw the traffic and exported the
  underlying records. It is identified by `emitter.observer`. Commonly the
  emitter and observer are the same software (a Cilium agent both observes
  traffic and emits connection logs), but they need not be: a converter such as
  Hubble CLC emits connection logs built from IPFIX flows exported by a separate
  observer (a smart switch). See [Emitters and observers](#emitters-and-observers).
- The **direction** of a `Connection` (its `source` and `destination`) is a
  property of the connection itself, independent of who emitted or observed it.

A `Connection` is directed: it has a `source` and a `destination`. These roles
are defined by the **direction in which the connection was initiated**, not by
where the connection was observed:

- **source** is the side that initiated the connection (the side that opened it,
  e.g. the sender of the TCP SYN or the process that owns the originating
  socket).
- **destination** is the side the connection was initiated towards.

This is a property of the connection itself. It does not depend on the vantage
point of the observer. An observer commonly sits at the source (for example, the
node hosting the connection initiator), which is why it is often described as
observing "at the source", but that is a typical deployment, not a rule. An
observer MAY see a connection from any vantage point (the source side, the
destination side, or somewhere in between).

The observer's vantage point is recorded separately, in the connection's
`observation_point` field (`OBSERVATION_POINT_SOURCE`, `_DESTINATION`, or
`_INTERMEDIATE`). This is distinct from source/destination: source and
destination always follow the initiation direction, while `observation_point`
says where the observation was made relative to that direction. An unset
`observation_point` is interpreted as `OBSERVATION_POINT_SOURCE`, matching the
typical source-side deployment. Because a single observer may see some
connections at the source and others at the destination, this is a
per-`Connection` field rather than a property of the `emitter`.

#### Emitters and observers

The `emitter` field carries both the emitter and the observer:

- `emitter.name` / `emitter.version` identify the software that **produced** the
  message.
- `emitter.observer` identifies the entity that **saw** the traffic:
  `observer.name` and `observer.version` are the observing software / OS /
  firmware and its version, and `observer.identifier` uniquely identifies the
  specific observer instance.

Emitters SHOULD populate `emitter.observer`. When the emitter observed the
traffic itself (for example a Cilium agent, which both sees the traffic and
writes the connection log), it may leave `observer` entirely unset: consumers
are expected to read `emitter.name` and `emitter.version` as the observer's name
and version. When the two differ (for example Hubble CLC turning a switch's
IPFIX flows into connection logs), set `observer` to describe the switch rather
than the converter.

That fallback applies to `observer` as a whole, not to its individual fields.
Once `observer` is set, an empty `observer.name` or `observer.version` stays
empty instead of inheriting the emitter's, so setting only `observer.identifier`
leaves the observer unnamed.

`observer.identifier` distinguishes multiple observers of the same kind so that
consumers can attribute each `ConnectionLog` to a specific instance and
deduplicate overlapping observations. Typical values are `cluster_name/node_name`
for a Cilium or Tetragon agent (the established Hubble convention), or the serial
number of a smart switch.

#### Return traffic is not a separate connection

Traffic flowing back from the destination to the source (for example, the
response to a request) does NOT produce a second `Connection` with the vertices
swapped. Instead, it is reported as the receive-side counters of the relevant
edge types on the **same** `Connection`. For example, on an A → B connection:

- bytes sent A → B are reported in `network_transmit_bytes_total`
- bytes sent B → A (the return traffic) are reported in
  `network_receive_bytes_total`

A `Connection` with `source = B, destination = A` only exists if B separately
*initiates* a connection towards A.

#### Multiple observers seeing the same connection

In a distributed deployment, more than one observer may see the same logical
connection (for example, the node hosting the source and the node hosting the
destination both observe A → B). When this happens:

- Each emitter MUST label the `source` and `destination` by connection
  direction, as defined above. Because direction is independent of the vantage
  point, all emitters produce the **same** source/destination labeling for the
  same connection.
- Each emitter SHOULD set a distinct `emitter.observer.identifier` so that
  consumers can attribute each `ConnectionLog` to a specific observer instance
  and deduplicate overlapping observations.
- Each emitter SHOULD set `observation_point` to record the observer's vantage
  point. For the A → B example, the observer at A's node reports
  `OBSERVATION_POINT_SOURCE` and the observer at B's node reports
  `OBSERVATION_POINT_DESTINATION`. This lets a consumer tell the two observations
  apart by vantage (and, in particular, know which one's counters reflect what B
  actually received; see below) without needing external knowledge of where
  each observer is deployed.

The "SHOULD NOT have overlapping time windows" constraint applies per observer
(identified by `observer.identifier`); different observers legitimately may emit
events covering the same vertex pair and time window.

#### Example: converting IPFIX flows to connection logs

A common deployment is a fleet of smart switches exporting IPFIX (or NetFlow)
flow records to a converter service (for example, Hubble CLC) that turns them
into connection logs. Here the observer (the switch) and the emitter (the
converter) are different entities, and the converter must take care to assign
`source` and `destination` by connection direction rather than by the fields of
an individual flow record.

The emitter/observer split is captured explicitly on the `emitter` field:

- `emitter.name` / `emitter.version` identify the **converter software** (e.g.
  `Hubble CLC` and its own version).
- `emitter.observer` identifies the **switch that exported the flows**:
  `observer.name` is the switch's NOS (e.g. `Nexus`), `observer.version` is the
  switch's NOS/firmware version, and `observer.identifier` is the switch's
  serial number or management IP.

This is exactly the distinction to get right: the converter's version belongs in
`emitter.version`, and the switch's firmware version belongs in
`observer.version`. Do not put the switch's version in `emitter.version`.

Two pitfalls to avoid:

1. **Do not map the IPFIX `sourceIPv4Address`/`sourceTransportPort` of a single
   flow record directly to the graph `source`.** A switch typically exports two
   unidirectional flow records for one bidirectional connection (A → B and
   B → A). Mapping each record's IPFIX "source" to the graph `source` produces
   two `Connection` messages with swapped vertices for a single logical
   connection, which contradicts the data model.

2. **Do not put the switch in the `source` vertex** just because it exported the
   flow. The switch is the *observer*; it belongs in `emitter.observer`, not in
   the vertices. The vertices are the flow endpoints.

Recommended approach:

- **Determine the initiator.** The graph `source` is the side that initiated the
  connection:
  - **TCP:** use the TCP flags (IPFIX `tcpControlBits`); the side that sent the
    initial SYN (without SYN-ACK) is the initiator.
  - **Biflow records (RFC 5103):** if the exporter includes reverse fields
    (e.g. `reverseOctetDeltaCount`), the record's forward direction is the
    initiation direction: use forward = source, reverse = destination.
  - **Fallback (UDP, or when flags are unavailable):** use a heuristic such as
    ephemeral port → well-known port (client → server), or first-seen packet
    ordering. This is best-effort, but the chosen rule MUST be applied
    consistently so the same connection always maps the same way across windows
    and switches (otherwise deduplication and time aggregation break).
- **Merge the two unidirectional flows into a single `Connection`.** Pair the
  A → B and B → A records of one connection and map forward traffic to the
  transmit-side counters and reverse traffic to the receive-side counters (e.g.
  `network_transmit_bytes_total` and `network_receive_bytes_total`). Emit one
  `Connection`, not two.
- **Set `emitter.observer` to the observing switch.** Stamp each
  `ConnectionLog`'s `emitter.observer` with the identity of the switch that
  observed it: `observer.identifier` = its serial number or management IP,
  `observer.name` = its NOS (e.g. `Nexus`), `observer.version` = its NOS or
  firmware version, not the converter's identity. When multiple switches on the
  path observe the same connection, distinct `observer.identifier` values let
  consumers deduplicate observations. The `emitter.name`/`emitter.version`
  identify the converter software; `emitter.observer` identifies the switch.
- **Set `observation_point` to `OBSERVATION_POINT_INTERMEDIATE`.** A switch on
  the path is neither the source nor the destination of the connection, so its
  observations describe transiting traffic rather than what either endpoint sent
  or received.

The resulting `emitter` field carries both the converted entities and the switch
entities it observed on behalf of:

```json5
{
  "emitter": {
    // The converter software that produced this message.
    "name": "Hubble CLC",
    "version": "1.2.0",
    // The switch that actually observed and exported the flows.
    "observer": {
      "name": "Nexus",          // the switch NOS, not the hardware model
      "version": "10.3.0",      // the switch's NOS/firmware version
      "identifier": "SN-1234567890"  // the switch serial number
    }
  }
  // ... window_start, window_end, connections with
  //     observation_point = OBSERVATION_POINT_INTERMEDIATE
}
```

#### Counters describe the observer's view, not end-to-end delivery

A `Connection`'s edge counters describe what the observer **saw at its own
vantage point**. They are not a confirmation of what the destination actually
received. On an A → B connection:

- `network_transmit_*` is what the observer saw put on the wire towards B.
- `network_receive_*` is what the observer saw arrive for this connection (the
  return traffic from B), as observed at the observer's location.

Neither counter, by itself, tells you what B received. This matters most for
protocols without delivery feedback: an observer at A's side counts UDP
datagrams as transmitted, but cannot know whether B received them. They may be
dropped anywhere downstream, and the emitted `Connection` looks identical either
way. (For TCP, `EdgeTypeL4Telemetry` retransmits and resets are an indirect,
source-observable signal of delivery problems; UDP has no equivalent.)

To determine what the destination actually received, you need an observation at
the destination's vantage point: a separate `ConnectionLog` whose observer sits
at (or near) B (i.e. with `observation_point = OBSERVATION_POINT_DESTINATION`),
where `network_receive_*` reflects B's reception. Computing delivery or loss
across the path is therefore a consumer-side, query-time operation that
correlates the source-side `transmit_*` with the destination-side `receive_*` of
the same connection, pairing the two observations by their vertices and
distinguishing their vantage points via `observation_point` (and
`observer.identifier`). A single `Connection` cannot express it.

`network_transmit_drop_total` and `network_receive_drop_total` report drops at
the observer itself (for example, a switch dropping on egress or ingress), with
the `_policy_total` fields as the policy-drop subset. These are local drops, not
a statement about what the destination received.

### Multicast connections

Multicast traffic has no single unicast destination: a feeder sends to a group
address that fans out to many receivers. To render this fan-out as what it is,
one feeder feeding a group and the group feeding many receivers, the graph API
represents each source-scoped stream as a first-class vertex that sits between
the feeder and its receivers, forming an explicit split.

The relevant fields are:

- `VertexFamilyMulticastStream` is a vertex family that represents a multicast
  stream. Its identity is the `(source_ip, group_ip, source_id)` tuple,
  with `source_id` omitted when unavailable. `source_ip` is the feeder's IP
  address, `group_ip` is the group address (validated to be in `224.0.0.0/4` or
  `ff00::/8`), and `source_id` is an optional identifier extracted from the
  stream, such as an MTP Line ID or RTP SSRC. A separate stream vertex is emitted
  for every observed source even under any-source multicast (ASM). This keeps
  the graph stable when a receiver uses source-specific multicast (SSM) to
  include or exclude a particular source.
- `VertexPropertyMulticast` (attachable to the other vertex families) carries the
  existing `source_id`/`group_ip` stream context as a property, so a feeder or
  receiver vertex can additionally be tagged with the group context it belongs
  to.
- `EdgeTypeMulticastTelemetry` carries `sequence_number_gap_count_total` and a
  `feeder_receiver_delay_histogram`. Both measure a receiver's experience of the
  stream (gaps it detected, delay it saw from the feeder), so this edge belongs
  on the stream-to-receiver connections, not on the feeder-to-stream connection.

Emit the fan-out as a two-hop split with the stream vertex in the middle:

1. **feeder to stream**: one `Connection` whose `source` is the feeder and whose
   `destination` is the `VertexFamilyMulticastStream`. Its edge telemetry
   describes the stream as emitted by the feeder.
2. **stream to receiver**: one `Connection` per receiver whose `source` is the
   same `VertexFamilyMulticastStream` and whose `destination` is the individual
   receiver (its own unicast IP). Its edge telemetry describes what that specific
   receiver got.

Because every stream-to-receiver connection shares the same stream vertex as
its source and the feeder-to-stream connection shares it as its destination,
the stream renders as a single split node: the feeder feeds into it and the
receivers fan out of it. Distinct streams (distinct
`(source_ip, group_ip, source_id)` tuples, with `source_id` omitted when
unavailable) render as distinct split nodes, so two feeders on the same
`group_ip` never collapse into one.

Direction follows data flow: multicast originates at the feeder and travels out
through the stream vertex to the receivers, so the feeder is the `source` of the
feeder-to-stream connection and the stream is the `source` of each
stream-to-receiver connection.

The rest of this section walks through one full example: feeder-01 sends group
`239.1.1.1` to two receivers, producing one feeder-to-stream connection and two
stream-to-receiver connections that all share the same stream vertex. All three
connections would typically be carried in a single `ConnectionLog` for the same
time window; they are shown as separate `Connection` objects below.

#### feeder to stream

The feeder-to-stream connection carries the stream as the feeder emitted it. It
carries `EdgeTypeNetworkTelemetry` transmit counters for what the feeder put on
the wire, and does not carry `EdgeTypeMulticastTelemetry`: gaps and
feeder-to-receiver delay are receiver-side measurements that only make sense on
the stream-to-receiver connections below. An emitter that only has feeder-side
data MAY emit just this connection and no stream-to-receiver connections.

```json5
{
  "source": {
    "network_device": {
      "name": "feeder-01",
      "ip": "10.0.0.1"
    }
  },
  "destination": {
    "multicast_stream": {
      "source_ip": "10.0.0.1",
      "group_ip": "239.1.1.1",
      "source_id": "123456"
    }
  },
  "links": [
    {
      "network_telemetry": {
        // What the feeder put on the wire for the group. This is a single
        // stream: 1000 packets are sent once, then replicated to receivers
        // downstream, not sent once per receiver.
        "network_transmit_packets_total": 1000,
        "network_transmit_bytes_total": 1460000
      }
    }
  ]
}
```

#### stream to receiver

Each stream-to-receiver connection describes what one receiver got. It is
observed at the receiver's vantage point (or the switch port facing it), so per
the "counters describe the observer's view" principle above, its
`network_receive_*` counters and `EdgeTypeMulticastTelemetry` (gaps, delay)
reflect that specific receiver's reception. Set `observation_point` to
`OBSERVATION_POINT_DESTINATION` when the observation is made at the receiver.

Here the two receivers of `239.1.1.1` are two connections that share the stream
vertex as their source. Comparing their `network_receive_*` counters against the
feeder's `network_transmit_*` above shows receiver-11 lost 20 of the 1000
packets the feeder sent, while receiver-12 received all of them.

```json5
{
  "source": {
    // The same stream vertex as the feeder-to-stream connection above, so all
    // three connections share one split node in the rendered graph.
    "multicast_stream": {
      "source_ip": "10.0.0.1",
      "group_ip": "239.1.1.1",
      "source_id": "123456"
    }
  },
  "destination": {
    "network_device": {
      "name": "receiver-11",
      "ip": "10.0.5.11"
    }
  },
  "links": [
    {
      "network_telemetry": {
        // What this receiver actually received from the group.
        "network_receive_packets_total": 980,
        "network_receive_bytes_total": 1430800
      }
    },
    {
      "multicast_telemetry": {
        // Gaps and delay observed at this receiver.
        "sequence_number_gap_count_total": 2,
        "feeder_receiver_delay_histogram": {
          "count_total": 980,
          "sum_total": 3100,
          "bucket_le_1ms_total": 600,
          "bucket_le_10ms_total": 900,
          "bucket_le_100ms_total": 970,
          "bucket_le_1s_total": 980
        }
      }
    }
  ]
}
```

```json5
{
  "source": {
    // Same stream vertex again: this is the second receiver fanning out of it.
    "multicast_stream": {
      "source_ip": "10.0.0.1",
      "group_ip": "239.1.1.1",
      "source_id": "123456"
    }
  },
  "destination": {
    "network_device": {
      "name": "receiver-12",
      "ip": "10.0.5.12"
    }
  },
  "links": [
    {
      "network_telemetry": {
        // This receiver got the full stream.
        "network_receive_packets_total": 1000,
        "network_receive_bytes_total": 1460000
      }
    },
    {
      "multicast_telemetry": {
        "sequence_number_gap_count_total": 0,
        "feeder_receiver_delay_histogram": {
          "count_total": 1000,
          "sum_total": 2500,
          "bucket_le_1ms_total": 700,
          "bucket_le_10ms_total": 960,
          "bucket_le_100ms_total": 1000,
          "bucket_le_1s_total": 1000
        }
      }
    }
  ]
}
```

Each receiver is its own `Connection` keyed by the receiver's IP, so a client
sees per-IP reception directly and can aggregate across the group at query time
by grouping on the stream vertex's `source_ip`, `group_ip`, and optional
`source_id`, exactly the query-time aggregation described below. This also
respects the scalar-vertex constraint: the receiver set is expressed as many
connections, never as a list packed into one vertex.

### Data aggregation

One of the core concepts of the graph API is data aggregation. With the concept
of a time window, data aggregates at the source that emits connection
events and also at query time to cover different time windows. Aggregation
drastically reduces the number of connection log messages to process. To enable
this property, all of the metadata on the edge of a connection must support
aggregation by some function, typically `SUM`.

#### How aggregation works

Design all edge properties to support aggregation using an appropriate function.
The aggregation function depends on the type of telemetry data:

- **Counters** (most common): aggregated using `SUM`
  - Examples: packet counts, byte counts, request counts, error counts
  - `total_packets = sum(packets_window1, packets_window2, ...)`

- **Histograms**: aggregated by summing bucket counts
  - Example: `EdgeTypeMulticastTelemetry.FeederReceiverDelayHistogram`
  - Each bucket count is summed independently across time windows

- **Future telemetry types** could use other aggregation functions:
  - `MAX`: for maximum latency observed
  - `MIN`: for minimum throughput observed
  - `AVG`: for average values (requires storing sum + count)
  - Percentiles or other statistical aggregates

The current API primarily uses counter-based telemetry (aggregated via `SUM`),
but the design supports extending to other aggregatable property types as new
edge types are added.

#### Source-time aggregation

At the source (emitter), connections are aggregated within a time window.
Instead of emitting a separate event for each individual observation, the
emitter aggregates all observations for the same vertex pair during the time
window into a single `Connection` with aggregated edge properties.

For example, if a data emitter observes HTTP traffic between Pod A and Pod B
during a 10-second window:

**Before aggregation (individual observations):**
```
t=0s:  Pod A → Pod B: 50 HTTP requests, 2 errors (4xx)
t=3s:  Pod A → Pod B: 30 HTTP requests, 0 errors
t=6s:  Pod A → Pod B: 45 HTTP requests, 1 error (5xx)
t=9s:  Pod A → Pod B: 25 HTTP requests, 3 errors (4xx)
```

**After source-time aggregation (single ConnectionLog):**
```json5
{
  "window_start": "t=0s",
  "window_end": "t=10s",
  "connections": [{
    "source": "Pod A",
    "destination": "Pod B",
    "links": [{
      "l7_telemetry": {
        "http_requests_total": 150,         // SUM: 50 + 30 + 45 + 25
        "http_client_errors_total": 5,      // SUM: 2 + 0 + 0 + 3
        "http_server_errors_total": 1       // SUM: 0 + 0 + 1 + 0
      }
    }]
  }]
}
```

This approach drastically reduces the number of events that need to be
transmitted, stored, and processed.

#### Query-time aggregation

At query time, clients can aggregate across multiple time windows or across
multiple connections by grouping vertices differently.

**Aggregating across time windows:**

Two `ConnectionLog` messages for the same vertex pair with consecutive time
windows can be aggregated to show totals over a longer period:

```
Window 1 (0-10s): Pod A → Pod B, 150 HTTP requests, 5 client errors
Window 2 (10-20s): Pod A → Pod B, 180 HTTP requests, 8 client errors
---
Aggregated (0-20s): Pod A → Pod B, 330 HTTP requests, 13 client errors
```

**Aggregating by grouping vertices:**

Clients can group connections by higher-level vertex attributes. For example,
instead of viewing pod-to-pod connections, group by namespace.

Before grouping (pod-level granularity):
```json5
// Connection 1
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-abc"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "api-xyz"}},
  "links": [{"l7_telemetry": {"http_requests_total": 150}}]
}

// Connection 2
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-def"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "api-xyz"}},
  "links": [{"l7_telemetry": {"http_requests_total": 120}}]
}

// Connection 3
{
  "source": {"kubernetes": {"namespace": "frontend", "pod_name": "web-abc"}},
  "destination": {"kubernetes": {"namespace": "backend", "pod_name": "db-mno"}},
  "links": [{"l7_telemetry": {"http_requests_total": 80}}]
}
```

After grouping by namespace (namespace-level granularity):
```json5
{
  "source": {"kubernetes": {"namespace": "frontend"}},
  "destination": {"kubernetes": {"namespace": "backend"}},
  "links": [{"l7_telemetry": {"http_requests_total": 350}}]  // SUM: 150 + 120 + 80
}
```

The client created a new aggregated vertex by selecting only the `namespace`
attribute and dropping pod-specific attributes like `pod_name`. All connections
sharing the same grouped source and destination are combined using the
aggregation function.

All edge properties must support aggregation to enable flexible aggregation at
any level without losing data fidelity. When adding new edge types, ensure all
properties have a well-defined aggregation function.

### Generic querying

Another core concept of the graph API is that while the source of connection
data may be very specific, which allows for database optimizations, the querying
facility is generic and flexible. In other words, clients can query for various
types of connections using the same query concepts. This property allows clients
to render graphs that represent varying data using the same rendering engine and code.

## Requirements for data emitters

### Emitting connection data with multiple edge types

Data emitters such as Hubble and Tetragon MUST include all applicable edge types
for a given connection within a single `Connection` message. Each connection is
defined by a unique pair of source and destination vertices, and the `links`
field contains all edge types that apply to that connection during the time
window.

For example, a TCP connection between Pod A and Pod B that carries HTTP traffic
requires emitting a **single** `Connection` per time window with:
- `source`: Pod A vertex properties
- `destination`: Pod B vertex properties
- `links`: array containing **multiple** edge types:
  - `EdgeTypeNetworkTelemetry` (packet counts, bytes, drops)
  - `EdgeTypeL4Telemetry` (TCP retransmits, resets, zero windows)
  - `EdgeTypeL7Telemetry` (HTTP request counts, error rates)

#### Correct approach
```json5
{
  "window_start": "2026-03-26T10:00:00Z",
  "window_end": "2026-03-26T10:00:10Z",
  "connections": [{
    "source": {
      "kubernetes": {
        "namespace": "frontend",
        "pod_name": "pod-a",
        "ip": "10.0.1.10",
        "port": 8080
      }
    },
    "destination": {
      "kubernetes": {
        "namespace": "backend",
        "pod_name": "pod-b",
        "ip": "10.0.2.20",
        "port": 9090
      }
    },
    "links": [
      {
        "network_telemetry": {
          "network_transmit_packets_total": 1500,
          "network_transmit_bytes_total": 750000
        }
      },
      {
        "l4_telemetry": {
          "tcp_retransmits_total": 2,
          "tcp_resets_total": 0
        }
      },
      {
        "l7_telemetry": {
          "http_requests_total": 350,
          "http_client_errors_total": 5
        }
      }
    ]
  }]
}
```

#### Incorrect approach (DO NOT DO THIS)
```json5
{
  // Don't emit separate connections for the same vertex pair
  "connections": [
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"network_telemetry": {"network_transmit_packets_total": 1500}}]
    },
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"l4_telemetry": {"tcp_retransmits_total": 2}}]
    },
    {
      "source": {"kubernetes": {"pod_name": "pod-a"}},
      "destination": {"kubernetes": {"pod_name": "pod-b"}},
      "links": [{"l7_telemetry": {"http_requests_total": 350}}]
    }
  ]
}
```

**Why this is incorrect**

This approach creates three separate `Connection` messages for the same vertex
pair (pod-a → pod-b), with each connection containing only one edge type. This
violates the data model: three connection objects consume more memory, bandwidth,
and storage than a single connection with three edges.

Instead, combine all edge types into a single `Connection` with multiple entries
in the `links` array, as shown in the correct example above.

Each edge type in the `links` array MUST be different. A connection cannot
include two `EdgeTypeNetworkTelemetry` edges, but can include one of each
available edge type that is relevant to the connection.

### Vertex property constraints

Vertex properties MUST be scalar values, not collections or complex types. This
constraint exists because clients create arbitrary vertices by grouping one or
more source and destination vertex attributes. Non-scalar properties require
unrolling or flattening. However, showing too much information in a graph
provides little value. Add unique identifiers to vertex properties so clients
can query other data sources to obtain more information about a given vertex.

#### Why scalar properties only?

When clients aggregate connections by grouping vertices, they select specific
vertex attributes to group by. This only works if properties are scalar values
that can be used as grouping keys.

For example, grouping by namespace works because namespace is a scalar string:
```
Group by: source.kubernetes.namespace
Result: All pods in "frontend" namespace are treated as one vertex
```

If properties were collections (arrays, maps), grouping becomes ambiguous:
- How does grouping work with an array of labels?
- Which element of the array defines the group?
- How do vertices with different array lengths get handled?

#### Best practices

1. **Keep it minimal**: Only include vertex properties that are useful for
   grouping and graph visualization. Graphs become cluttered with too much
   information.

2. **Use identifiers**: For complex metadata, store a UID in the vertex and let
   clients query external systems (Kubernetes API, Timescape, etc.) for details.

3. **Connection-specific values**: Vertex properties should reflect the values
   relevant to that specific connection. If a pod has multiple IPs, use the IP
   actually involved in the connection.

4. **Think about grouping**: Ask "would someone want to group by this property?"
   If no, consider whether it belongs in the vertex at all.

## Validation rules

This section documents all the mandatory (MUST/MUST NOT) and recommended
(SHOULD/SHOULD NOT) constraints for implementing and using the graph API.

### ConnectionLog constraints

**MUST:**
- Each `ConnectionLog` MUST have a unique `uuid` to identify the event
- `window_start` MUST be before `window_end`
- The `connections` array MUST contain at least one `Connection` if the
  ConnectionLog is emitted (emitters MAY choose not to emit if no connections
  were observed)

**SHOULD NOT:**
- Emitters SHOULD NOT re-emit the same `ConnectionLog` events (identified by
  `uuid`)
- `ConnectionLog` events SHOULD NOT have overlapping time windows for the same
  vertex pairs from the same observer (identified by `observer.identifier`)

### Connection constraints

**MUST:**
- Each `Connection` MUST have exactly one `source` vertex
- Each `Connection` MUST have exactly one `destination` vertex
- The `links` array MUST contain at least one `Edge`
- If multiple edges are provided in `links`, each edge type MUST be different
  (e.g., a connection cannot have two `EdgeTypeNetworkTelemetry` edges in the
  same connection)

**MUST NOT:**
- Do NOT emit multiple separate `Connection` messages for the same source and
  destination vertex pair within the same time window. Instead, combine all edge
  types into a single `Connection` with multiple entries in the `links` array.

### Vertex constraints

**MUST:**
- All vertex properties MUST be scalar values (strings, numbers, enums)
- Each vertex MUST belong to exactly one vertex family (e.g., `kubernetes`,
  `network_device`, `world_entity`, or `multicast_stream`)
- Vertex properties MUST represent values relevant to the specific connection
  being described

**MUST NOT:**
- Vertex properties MUST NOT be collections (arrays, maps) or complex nested
  objects
- Vertex properties MUST NOT contain non-scalar data without flattening it first

### Edge constraints

**MUST:**
- All edge properties MUST be aggregatable using a well-defined function
  (typically `SUM` for counters, bucket summation for histograms)
- Edge property names for counters SHOULD use the `_total` suffix to indicate
  they are cumulative values over the time window
- Each edge MUST belong to exactly one edge type (e.g., `network_telemetry`,
  `l4_telemetry`, `l7_telemetry`, etc.)

### Data emitter requirements

**MUST:**
- Emitters MUST include all applicable edge types for a connection in a single
  `Connection` message
- Emitters MUST aggregate observations within their time window before emitting
- Emitters MUST set both `window_start` and `window_end` to define the
  aggregation period
- Emitters MUST populate the `emitter` field to identify the source of the data

**SHOULD:**
- Emitters SHOULD use non-overlapping time windows for better query-time
  aggregation
- Emitters SHOULD emit ConnectionLog events at regular intervals
- Time windows SHOULD be aligned to regular boundaries (e.g., every 10 seconds
  starting at :00, :10, :20, etc.)
- Emitters SHOULD populate `emitter.observer`, and in particular
  `observer.identifier`, so consumers can attribute events to a specific
  observer instance and deduplicate. This matters when multiple observers run
  concurrently (e.g., one Cilium agent per node, or a fleet of smart switches).
  An emitter that sets `observer` SHOULD set all of its fields: only an entirely
  unset `observer` falls back to the emitter's name and version.
