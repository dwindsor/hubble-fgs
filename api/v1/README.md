# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [fgs.proto](#fgs.proto)
    - [Container](#fgs.Container)
    - [Filter](#fgs.Filter)
    - [GetEventsRequest](#fgs.GetEventsRequest)
    - [GetEventsResponse](#fgs.GetEventsResponse)
    - [GetHealthStatusRequest](#fgs.GetHealthStatusRequest)
    - [GetHealthStatusResponse](#fgs.GetHealthStatusResponse)
    - [HealthStatus](#fgs.HealthStatus)
    - [Image](#fgs.Image)
    - [Pod](#fgs.Pod)
    - [Process](#fgs.Process)
    - [ProcessAccept](#fgs.ProcessAccept)
    - [ProcessClose](#fgs.ProcessClose)
    - [ProcessConnect](#fgs.ProcessConnect)
    - [ProcessExec](#fgs.ProcessExec)
    - [ProcessExit](#fgs.ProcessExit)
    - [ProcessListen](#fgs.ProcessListen)
    - [Test](#fgs.Test)
    - [Tls](#fgs.Tls)
  
    - [EventType](#fgs.EventType)
    - [HealthStatusResult](#fgs.HealthStatusResult)
    - [HealthStatusType](#fgs.HealthStatusType)
  
    - [FineGuidanceSensors](#fgs.FineGuidanceSensors)
  
- [Scalar Value Types](#scalar-value-types)



<a name="fgs.proto"></a>
<p align="right"><a href="#top">Top</a></p>

## fgs.proto



<a name="fgs.Container"></a>

### Container



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| name | [string](#string) |  |  |
| image | [Image](#fgs.Image) |  |  |
| start_time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Start time of the container. |
| pid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  | PID in the container namespace. |
| maybe_exec_probe | [bool](#bool) |  | If this is set true, it means that the process might have been originated from a Kubernetes exec probe. For this field to be true, the following must be true:

1. The binary field matches the first element of the exec command list for either liveness or readiness probe excluding the basename. For example, &#34;/bin/ls&#34; and &#34;ls&#34; are considered a match. 2. The arguments field exactly matches the rest of the exec command list. |






<a name="fgs.Filter"></a>

### Filter



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| binary_regex | [string](#string) | repeated |  |
| namespace | [string](#string) | repeated |  |
| health_check | [google.protobuf.BoolValue](#google.protobuf.BoolValue) |  |  |
| pid | [uint32](#uint32) | repeated |  |
| pid_set | [uint32](#uint32) | repeated |  |
| event_set | [EventType](#fgs.EventType) | repeated |  |






<a name="fgs.GetEventsRequest"></a>

### GetEventsRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| allow_list | [Filter](#fgs.Filter) | repeated | allow_list specifies a list of filters to apply to only return certain events. If multiple filters are specified, at least one of them has to match for an event to be included in the results. |
| deny_list | [Filter](#fgs.Filter) | repeated | deny_list specifies a list of filters to apply to exclude certain events from the results. If multiple filters are specified, at least one of them has to match for an event to be excluded.

If both allow_list and deny_list are specified, the results contain the set difference allow_list - deny_list. |






<a name="fgs.GetEventsResponse"></a>

### GetEventsResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process_exec | [ProcessExec](#fgs.ProcessExec) |  |  |
| process_connect | [ProcessConnect](#fgs.ProcessConnect) |  |  |
| process_listen | [ProcessListen](#fgs.ProcessListen) |  |  |
| tls | [Tls](#fgs.Tls) |  |  |
| process_exit | [ProcessExit](#fgs.ProcessExit) |  |  |
| process_close | [ProcessClose](#fgs.ProcessClose) |  |  |
| process_accept | [ProcessAccept](#fgs.ProcessAccept) |  |  |
| test | [Test](#fgs.Test) |  |  |
| node_name | [string](#string) |  | Name of the node where this event was observed. |
| time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  | Timestamp at which this event was observed. |






<a name="fgs.GetHealthStatusRequest"></a>

### GetHealthStatusRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event_set | [HealthStatusType](#fgs.HealthStatusType) | repeated |  |






<a name="fgs.GetHealthStatusResponse"></a>

### GetHealthStatusResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| health_status | [HealthStatus](#fgs.HealthStatus) | repeated |  |






<a name="fgs.HealthStatus"></a>

### HealthStatus



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| event | [HealthStatusType](#fgs.HealthStatusType) |  |  |
| status | [HealthStatusResult](#fgs.HealthStatusResult) |  |  |
| details | [string](#string) |  |  |






<a name="fgs.Image"></a>

### Image



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  |  |
| name | [string](#string) |  |  |






<a name="fgs.Pod"></a>

### Pod



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespace | [string](#string) |  |  |
| name | [string](#string) |  |  |
| labels | [string](#string) | repeated |  |
| container | [Container](#fgs.Container) |  |  |






<a name="fgs.Process"></a>

### Process



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| exec_id | [string](#string) |  | Exec ID uniquely identifies the process over time across all the nodes in the cluster. |
| pid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| uid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| cwd | [string](#string) |  |  |
| binary | [string](#string) |  |  |
| arguments | [string](#string) |  |  |
| flags | [string](#string) |  |  |
| start_time | [google.protobuf.Timestamp](#google.protobuf.Timestamp) |  |  |
| auid | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| pod | [Pod](#fgs.Pod) |  |  |
| docker | [string](#string) |  |  |
| parent_exec_id | [string](#string) |  |  |
| refcnt | [uint32](#uint32) |  |  |






<a name="fgs.ProcessAccept"></a>

### ProcessAccept



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |






<a name="fgs.ProcessClose"></a>

### ProcessClose



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |






<a name="fgs.ProcessConnect"></a>

### ProcessConnect



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_names | [string](#string) | repeated |  |






<a name="fgs.ProcessExec"></a>

### ProcessExec



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |
| ancestors | [Process](#fgs.Process) | repeated | Ancestors of the process beyond the immediate parent. |






<a name="fgs.ProcessExit"></a>

### ProcessExit



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |






<a name="fgs.ProcessListen"></a>

### ProcessListen



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| parent | [Process](#fgs.Process) |  |  |
| ip | [string](#string) |  |  |
| port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |






<a name="fgs.Test"></a>

### Test







<a name="fgs.Tls"></a>

### Tls



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| process | [Process](#fgs.Process) |  |  |
| source_ip | [string](#string) |  |  |
| source_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| destination_ip | [string](#string) |  |  |
| destination_port | [google.protobuf.UInt32Value](#google.protobuf.UInt32Value) |  |  |
| negotiated_version | [string](#string) |  |  |
| supported_versions | [string](#string) |  |  |
| sni_type | [string](#string) |  |  |
| sni_name | [string](#string) |  |  |
| cipher | [string](#string) |  |  |
| client_flags | [string](#string) |  |  |
| server_flags | [string](#string) |  |  |
| client_version | [string](#string) |  |  |
| server_version | [string](#string) |  |  |
| client_alert | [string](#string) |  |  |
| server_alert | [string](#string) |  |  |
| client_session | [string](#string) |  |  |
| server_session | [string](#string) |  |  |





 


<a name="fgs.EventType"></a>

### EventType
EventType constants are based on the ones from pkg/api/client

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNDEF | 0 |  |
| PROCESS_CONNECT | 1 |  |
| PROCESS_LISTEN | 4 |  |
| PROCESS_EXEC | 5 |  |
| PROCESS_TLS | 6 |  |
| PROCESS_EXIT | 7 |  |
| PROCESS_CLOSE | 8 |  |
| PROCESS_ACCEPT | 9 |  |
| TEST | 254 |  |



<a name="fgs.HealthStatusResult"></a>

### HealthStatusResult


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_UNDEF | 0 |  |
| HEALTH_STATUS_RUNNING | 1 |  |
| HEALTH_STATUS_STOPPED | 2 |  |
| HEALTH_STATUS_ERROR | 3 |  |



<a name="fgs.HealthStatusType"></a>

### HealthStatusType


| Name | Number | Description |
| ---- | ------ | ----------- |
| HEALTH_STATUS_TYPE_UNDEF | 0 |  |
| HEALTH_STATUS_TYPE_STATUS | 1 |  |


 

 


<a name="fgs.FineGuidanceSensors"></a>

### FineGuidanceSensors


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetEvents | [GetEventsRequest](#fgs.GetEventsRequest) | [GetEventsResponse](#fgs.GetEventsResponse) stream |  |
| GetHealth | [GetHealthStatusRequest](#fgs.GetHealthStatusRequest) | [GetHealthStatusResponse](#fgs.GetHealthStatusResponse) |  |

 



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

