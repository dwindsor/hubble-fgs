# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [graph/v1alpha/edge.proto](#graph_v1alpha_edge-proto)
    - [Edge](#graph-v1alpha-Edge)
    - [EdgeTypeBasic](#graph-v1alpha-EdgeTypeBasic)
    - [EdgeTypeL4Telemetry](#graph-v1alpha-EdgeTypeL4Telemetry)
    - [EdgeTypeL7Telemetry](#graph-v1alpha-EdgeTypeL7Telemetry)
    - [EdgeTypeMulticastTelemetry](#graph-v1alpha-EdgeTypeMulticastTelemetry)
    - [EdgeTypeMulticastTelemetry.FeederReceiverDelayHistogram](#graph-v1alpha-EdgeTypeMulticastTelemetry-FeederReceiverDelayHistogram)
    - [EdgeTypeNetworkTelemetry](#graph-v1alpha-EdgeTypeNetworkTelemetry)
    - [EdgeTypeRoutingTelemetry](#graph-v1alpha-EdgeTypeRoutingTelemetry)
  
- [graph/v1alpha/vertex.proto](#graph_v1alpha_vertex-proto)
    - [Vertex](#graph-v1alpha-Vertex)
    - [VertexFamilyKubernetes](#graph-v1alpha-VertexFamilyKubernetes)
    - [VertexFamilyMulticastStream](#graph-v1alpha-VertexFamilyMulticastStream)
    - [VertexFamilyNetworkDevice](#graph-v1alpha-VertexFamilyNetworkDevice)
    - [VertexFamilyWorldEntity](#graph-v1alpha-VertexFamilyWorldEntity)
    - [VertexPropertyMulticast](#graph-v1alpha-VertexPropertyMulticast)
  
- [graph/v1alpha/connection.proto](#graph_v1alpha_connection-proto)
    - [Connection](#graph-v1alpha-Connection)
    - [ConnectionLog](#graph-v1alpha-ConnectionLog)
  
    - [ObservationPoint](#graph-v1alpha-ObservationPoint)
  
- [Scalar Value Types](#scalar-value-types)



<a name="graph_v1alpha_edge-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/edge.proto



<a name="graph-v1alpha-Edge"></a>

### Edge
An edge represents aggregatable properties of a given connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| basic | [EdgeTypeBasic](#graph-v1alpha-EdgeTypeBasic) |  |  |
| network_telemetry | [EdgeTypeNetworkTelemetry](#graph-v1alpha-EdgeTypeNetworkTelemetry) |  |  |
| routing_telemetry | [EdgeTypeRoutingTelemetry](#graph-v1alpha-EdgeTypeRoutingTelemetry) |  |  |
| l4_telemetry | [EdgeTypeL4Telemetry](#graph-v1alpha-EdgeTypeL4Telemetry) |  |  |
| l7_telemetry | [EdgeTypeL7Telemetry](#graph-v1alpha-EdgeTypeL7Telemetry) |  |  |
| multicast_telemetry | [EdgeTypeMulticastTelemetry](#graph-v1alpha-EdgeTypeMulticastTelemetry) |  |  |






<a name="graph-v1alpha-EdgeTypeBasic"></a>

### EdgeTypeBasic
EdgeTypeBasic is a base edge that does not carry any information.






<a name="graph-v1alpha-EdgeTypeL4Telemetry"></a>

### EdgeTypeL4Telemetry
EdgeTypeL4Telemetry provides telemetry information regarding a network
connection at the transport layer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| tcp_retransmits_total | [uint64](#uint64) |  | tcp_retransmits_total is the number of TCP segments that have been retransmitted during the selected time window. |
| tcp_zero_window_total | [uint64](#uint64) |  | tcp_zero_window_total is the number of times a zero TCP window has been observed during the selected time window. |
| tcp_resets_total | [uint64](#uint64) |  | tcp_resets_total is the number of TCP resets that have been observed during the selected time window. |






<a name="graph-v1alpha-EdgeTypeL7Telemetry"></a>

### EdgeTypeL7Telemetry
EdgeTypeL7Telemetry provides telemetry information regarding a network
connection at the application layer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| http_requests_total | [uint64](#uint64) |  | http_requests_total is the number of HTTP requests that occurred during the selected time window. In conjunction with http_server_errors_total and http_client_errors_total, one can determine the error rate as a percent of requests that are failing from the total number of requests. One can also measure throughput in terms of HTTP requests per second. |
| http_server_errors_total | [uint64](#uint64) |  | http_server_errors_total is the number of HTTP server errors (5xx) that occurred during the selected time window. |
| http_client_errors_total | [uint64](#uint64) |  | http_client_errors_total is the number of HTTP client errors (4xx) that occurred during the selected time window. |






<a name="graph-v1alpha-EdgeTypeMulticastTelemetry"></a>

### EdgeTypeMulticastTelemetry
EdgeTypeMulticastTelemetry provides telemetry information regarding a
multicast connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| sequence_number_gap_count_total | [uint64](#uint64) |  | sequence_number_gap_count_total is the number of sequence number gaps detected. |
| feeder_receiver_delay_histogram | [EdgeTypeMulticastTelemetry.FeederReceiverDelayHistogram](#graph-v1alpha-EdgeTypeMulticastTelemetry-FeederReceiverDelayHistogram) |  | feeder_receiver_delay_histogram captures a histogram of delays experienced by multicast receivers from feeders. |






<a name="graph-v1alpha-EdgeTypeMulticastTelemetry-FeederReceiverDelayHistogram"></a>

### EdgeTypeMulticastTelemetry.FeederReceiverDelayHistogram
FeederReceiverDelayHistogram represents a cumulative histogram with
hardcoded buckets for delays experienced by multicast receivers from
feeders.

The histogram model is based on Prometheus classic histograms, with the
difference that it does not include the upper bound bucket (le=&#34;&#43;Inf&#34;) for
space efficiency. When computing rates, averages or quantiles, the
count_total field can be used instead.
Prometheus docs: https://prometheus.io/docs/concepts/metric_types/#histogram.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| count_total | [uint64](#uint64) |  | count_total is the total number of observations. Use this to interpret the upper bound bucket (le=&#34;&#43;Inf&#34;) in higher level calculations. |
| sum_total | [uint64](#uint64) |  | sum_total is the sum of all observed values, in milliseconds. |
| bucket_le_1ms_total | [uint64](#uint64) |  | bucket_le_1ms_total is the number of observations less than or equal to 1ms. |
| bucket_le_10ms_total | [uint64](#uint64) |  | bucket_le_10ms_total is the number of observations less than or equal to 10ms. |
| bucket_le_100ms_total | [uint64](#uint64) |  | bucket_le_100ms_total is the number of observations less than or equal to 100ms. |
| bucket_le_1s_total | [uint64](#uint64) |  | bucket_le_1s_total is the number of observations less than or equal to 1s. |






<a name="graph-v1alpha-EdgeTypeNetworkTelemetry"></a>

### EdgeTypeNetworkTelemetry
EdgeTypeNetworkTelemetry provides telemetry information regarding a network
connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network_transmit_packets_total | [uint64](#uint64) |  | network_transmit_packets_total is the number of packets transferred during the selected time window. |
| network_transmit_bytes_total | [uint64](#uint64) |  | network_transmit_bytes_total is the number of bytes transferred during the selected time window. |
| network_transmit_drop_total | [uint64](#uint64) |  | network_transmit_drop_total is the number of transmit packets dropped during the selected time window. |
| network_transmit_drop_policy_total | [uint64](#uint64) |  | network_transmit_drop_policy_total is the number of transmit packets dropped due to a network policy during the selected time window. It is always a subset of network_transmit_drop_total. |
| network_receive_packets_total | [uint64](#uint64) |  | network_receive_packets_total is the number of packets received during the selected time window. |
| network_receive_bytes_total | [uint64](#uint64) |  | network_receive_bytes_total is the number of bytes received during the selected time window. |
| network_receive_drop_total | [uint64](#uint64) |  | network_receive_drop_total is the number of received packets discarded during the selected time window. |
| network_receive_drop_policy_total | [uint64](#uint64) |  | network_receive_drop_policy_total is the number of received packets dropped due to a network policy during the selected time window. It is always a subset of network_receive_drop_total. |






<a name="graph-v1alpha-EdgeTypeRoutingTelemetry"></a>

### EdgeTypeRoutingTelemetry
EdgeTypeRoutingTelemetry provides telemetry information regarding routing
decisions.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| routing_forwarded_total | [uint64](#uint64) |  | routing_forwarded_total is the number of network flows that have been forwarded to the next processing entity. |
| routing_dropped_total | [uint64](#uint64) |  | routing_dropped_total is the number of network flows that have been dropped. Reasons for dropping data may be due to a malformed packet, rejection by a network policy, etc. |
| routing_dropped_policy_total | [uint64](#uint64) |  | routing_dropped_policy_total is the number of network flows that have been dropped because of a network policy. It is always a subset of routing_dropped_total. |
| routing_error_total | [uint64](#uint64) |  | routing_error_total is the number of flows where an error occurred during processing. |
| routing_audit_total | [uint64](#uint64) |  | routing_audit_total is the number of times a flow would have been dropped if a network policy that applies to it was enforced. |
| routing_redirected_total | [uint64](#uint64) |  | routing_redirected_total is the number of flows which have been redirected, for instance to a local proxy. |
| routing_traced_total | [uint64](#uint64) |  | routing_traced_total is the number of flows that have been observed at a trace point. |
| routing_translated_total | [uint64](#uint64) |  | routing_translated_total is the number of flows where are address has been translated. |





 

 

 

 



<a name="graph_v1alpha_vertex-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/vertex.proto



<a name="graph-v1alpha-Vertex"></a>

### Vertex
A vertex represents a set of properties of a connection source or
destination.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| kubernetes | [VertexFamilyKubernetes](#graph-v1alpha-VertexFamilyKubernetes) |  |  |
| network_device | [VertexFamilyNetworkDevice](#graph-v1alpha-VertexFamilyNetworkDevice) |  |  |
| world_entity | [VertexFamilyWorldEntity](#graph-v1alpha-VertexFamilyWorldEntity) |  |  |
| multicast_stream | [VertexFamilyMulticastStream](#graph-v1alpha-VertexFamilyMulticastStream) |  |  |






<a name="graph-v1alpha-VertexFamilyKubernetes"></a>

### VertexFamilyKubernetes
VertexFamilyKubernetes represent vertex properties that are related to a
Kubernetes context.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uid | [string](#string) |  | UID is the unique in time and space value of the Kubernetes object. |
| resource_kind | [common.k8s.type.v1alpha.ResourceKind](#common-k8s-type-v1alpha-ResourceKind) |  | resource_kind defines the type of Kubernetes resource. |
| resource_version | [string](#string) |  | resource_version is an opaque value that represents the internal version of the Kubernetes object. |
| resource_name | [string](#string) |  | resource_name is the name of the Kubernetes object which is unique within a namespace. |
| cluster_name | [string](#string) |  | cluster_name is the name of the Kubernetes cluster. |
| namespace | [string](#string) |  | namespace is the space within which each resource name is unique. |
| node_name | [string](#string) |  | node_name is the name of the Kubernetes node. |
| pod_name | [string](#string) |  | pod_name is the name of the Kubernetes pod. |
| container_name | [string](#string) |  | container_name is the name of the container. |
| service_kind | [common.k8s.type.v1alpha.ServiceKind](#common-k8s-type-v1alpha-ServiceKind) |  | service_kind represents the type of the Kubernetes service. The service_kind field should be set when the resource_kind field is RESOURCE_KIND_SERVICE. |
| workload_kind | [common.k8s.type.v1alpha.WorkloadKind](#common-k8s-type-v1alpha-WorkloadKind) |  | workload_kind represents the type of the Kubernetes workload. The workload_kind should be set when the resource_kind field is set to RESOURCE_KIND_WORKLOAD. |
| ip | [string](#string) |  | ip is a network address that can be associated with the Kubernetes resource and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |
| ip_protocol | [common.net.v1alpha.IPProtocol](#common-net-v1alpha-IPProtocol) |  | protocol is the protocol that is used for the connection at the L3/L4 layer. |
| application_model_uuid | [string](#string) |  | application_model_uuid is a unique identifier that identifies the application model associated with the Kubernetes resource. |
| interface_name | [string](#string) |  | interface_name is the name of the network interface associated with the connection. |
| multicast | [VertexPropertyMulticast](#graph-v1alpha-VertexPropertyMulticast) |  | multicast contains multicast specific information. |






<a name="graph-v1alpha-VertexFamilyMulticastStream"></a>

### VertexFamilyMulticastStream
VertexFamilyMulticastStream represents a source-scoped multicast stream as a
first-class vertex so that the fan-out from a feeder to multiple receivers
can be rendered as an explicit split. The vertex identity is the (source_ip,
group_ip, source_id) tuple, with source_id omitted when the stream has no
payload-level identifier. Distinct sources sending to the same group address
are represented as distinct vertices, each rooting its own distribution tree.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_ip | [string](#string) |  | source_ip is the IP address of the source of the multicast traffic. It is always set so that the stream can be correlated with source-specific multicast membership reports. |
| group_ip | [string](#string) |  | group_ip is the multicast group address that identifies the group. It is always a valid multicast address. |
| source_id | [string](#string) |  | source_id is an optional identifier extracted from the multicast stream, such as an MTP Line ID or RTP SSRC. |






<a name="graph-v1alpha-VertexFamilyNetworkDevice"></a>

### VertexFamilyNetworkDevice
VertexFamilyNetworkDevice represents vertex properties that are related to a
network device.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | name is the name of the network device. |
| ip | [string](#string) |  | ip is a network address that can be associated with the network device and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |
| ip_protocol | [common.net.v1alpha.IPProtocol](#common-net-v1alpha-IPProtocol) |  | protocol is the protocol that is used for the connection at the L3/L4 layer. |
| application_protocol | [string](#string) |  | application_protocol is the layer 7 protocol used for the connection. |
| vlan_name | [string](#string) |  | vlan_name is a human readable name associated with a VLAN ID. |
| vlan_id | [uint32](#uint32) |  | vlan_id is an ID in the range 1 to 4094 that defines a broadcast domain at the data link layer. |
| vrf_name | [string](#string) |  | vrf_name is the name of a virtual routing and forwarding segement that is the equivalent of a VLAN but at the network layer. |
| interface_name | [string](#string) |  | interface_name is the name of the network interface associated with the connection. |
| multicast | [VertexPropertyMulticast](#graph-v1alpha-VertexPropertyMulticast) |  | multicast contains multicast specific information. |






<a name="graph-v1alpha-VertexFamilyWorldEntity"></a>

### VertexFamilyWorldEntity
VertexFamilyWorldEntity represents a broad set of network elements outside
of a specific network boundary.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| dns_name | [string](#string) |  | dns_name is the DNS name that can be associated with the world entity. |
| ip | [string](#string) |  | ip is a network address that can be associated with the world entity and the connection. |
| port | [uint32](#uint32) |  | port is the network port associated with the ip address. |
| ip_protocol | [common.net.v1alpha.IPProtocol](#common-net-v1alpha-IPProtocol) |  | protocol is the protocol that is used for the connection at the L3/L4 layer. |
| multicast | [VertexPropertyMulticast](#graph-v1alpha-VertexPropertyMulticast) |  | multicast contains multicast specific information. |






<a name="graph-v1alpha-VertexPropertyMulticast"></a>

### VertexPropertyMulticast
VertexPropertyMulticast contains multicast specific information for a vertex.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source_id | [string](#string) |  | source_id is an optional identifier extracted from the multicast stream, such as an MTP Line ID or RTP SSRC. |
| group_ip | [string](#string) |  | group_ip is the multicast group address associated with the connection. |





 

 

 

 



<a name="graph_v1alpha_connection-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## graph/v1alpha/connection.proto



<a name="graph-v1alpha-Connection"></a>

### Connection
A connection is a simple directed graph where an edge links two vertices in
one direction.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| source | [Vertex](#graph-v1alpha-Vertex) |  | Source defines properties of the vertex that initiated the connection, i.e. the side that opened the connection (for example, the sender of the TCP SYN or the process that owns the originating socket).

Source and destination are defined by the direction in which the connection was initiated, independent of which emitter observed it. Two emitters observing the same connection from different vantage points (for example, the nodes hosting the source and the destination) MUST label the source and destination identically, so that consumers can deduplicate using the emitter&#39;s source_identifier. |
| destination | [Vertex](#graph-v1alpha-Vertex) |  | Destination defines properties of the vertex that received the connection, i.e. the side that the source initiated the connection towards.

Return traffic from the destination back to the source is NOT a separate connection: it is reported as the receive-side counters of the edge types on this same Connection (for example, EdgeTypeNetworkTelemetry.network_receive_bytes_total). |
| links | [Edge](#graph-v1alpha-Edge) | repeated | Links define properties of the edges that link the two vertices.

There MUST be at least one link between the source and destination vertices.

If more than one link is provided, their type MUST be different. In other words, links MUST be a set of at least one element where every element in the set is of a different edge type. |
| observation_point | [ObservationPoint](#graph-v1alpha-ObservationPoint) |  | Observation point is the vantage point, relative to this connection&#39;s direction, from which the observer saw it. The observer is the entity that actually saw the traffic, which is not necessarily the emitter that produced this message (see common.v1alpha.Emitter.observer): for a converter such as Hubble CLC, the observer is the switch that exported the flows, not the converter. The observation point does NOT change the source/destination labeling (which always follows the initiation direction); it records where along the path the observation was made so that consumers can interpret the edge counters and reconcile multiple observations of the same connection.

A single observer (for example, a node-local agent) commonly observes some connections at the source (those initiated by local workloads) and others at the destination (those initiated towards local workloads) within the same ConnectionLog. |






<a name="graph-v1alpha-ConnectionLog"></a>

### ConnectionLog
A connection log is a message that a source emits periodically and which
provides information about connections.

Emitters SHOULD NOT re-emit ConnectionLog events.
ConnectionLog events SHOULD NOT have overlapping time windows.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| uuid | [string](#string) |  | Uuid is a universally unique identifier for this event. |
| emitter | [common.v1alpha.Emitter](#common-v1alpha-Emitter) |  | An emitter is the entity that produces this message. It commonly also observes the connection information itself (for example, a Cilium agent running on the node that hosts the connection initiator), but this is not required: an emitter MAY be a converter that produces connection logs from records exported by a separate observer (for example, Hubble CLC turning a smart switch&#39;s IPFIX flows into connection logs). The entity that actually observed the traffic is recorded in emitter.observer, and its vantage point in each connection&#39;s observation_point. Regardless of where the observation was made, the source and destination of each connection MUST be labeled by the direction in which the connection was initiated (see Connection). |
| window_start | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window start is the time at which the emitter started collecting information regarding the observed connections. |
| window_end | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | Window end is the time at which the emitter stopped collecting information regarding the observed connections. |
| connections | [Connection](#graph-v1alpha-Connection) | repeated | Connections is a list of all connections that were tracked during the given time window. |





 


<a name="graph-v1alpha-ObservationPoint"></a>

### ObservationPoint
ObservationPoint identifies, relative to a connection&#39;s direction, the
vantage point from which the observer saw the connection. The edge counters
of a Connection describe what the observer saw at this vantage point, so the
observation point tells consumers whether the transmit-side or the
receive-side counters are authoritative for a given side of the connection.

| Name | Number | Description |
| ---- | ------ | ----------- |
| OBSERVATION_POINT_UNSPECIFIED | 0 | OBSERVATION_POINT_UNSPECIFIED indicates the observer did not declare its vantage point. Consumers SHOULD interpret an unspecified observation point as OBSERVATION_POINT_SOURCE: an observer commonly runs at the source (the connection initiator), so this is the assumed default. |
| OBSERVATION_POINT_SOURCE | 1 | OBSERVATION_POINT_SOURCE indicates the observer saw the connection at the source (initiator) side. |
| OBSERVATION_POINT_DESTINATION | 2 | OBSERVATION_POINT_DESTINATION indicates the observer saw the connection at the destination side, i.e. the side the connection was initiated towards. |
| OBSERVATION_POINT_INTERMEDIATE | 3 | OBSERVATION_POINT_INTERMEDIATE indicates the observer saw the connection at an intermediate point on the path, neither the source nor the destination (for example, a switch exporting IPFIX flow records for traffic transiting it). |


 

 

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

