# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [application_model/v1alpha/application_model.proto](#application_model_v1alpha_application_model-proto)
    - [ApplicationConnection](#application_model-v1alpha-ApplicationConnection)
    - [ApplicationHost](#application_model-v1alpha-ApplicationHost)
    - [ApplicationModel](#application_model-v1alpha-ApplicationModel)
    - [ApplicationModelEvent](#application_model-v1alpha-ApplicationModelEvent)
    - [ApplicationNamespace](#application_model-v1alpha-ApplicationNamespace)
    - [ApplicationProcess](#application_model-v1alpha-ApplicationProcess)
    - [ApplicationWorkload](#application_model-v1alpha-ApplicationWorkload)
  
- [Scalar Value Types](#scalar-value-types)



<a name="application_model_v1alpha_application_model-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## application_model/v1alpha/application_model.proto



<a name="application_model-v1alpha-ApplicationConnection"></a>

### ApplicationConnection



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| destination_name | [string](#string) |  |  |
| destination_port | [uint64](#uint64) |  |  |
| bytes_sent | [uint64](#uint64) |  |  |
| bytes_received | [uint64](#uint64) |  |  |






<a name="application_model-v1alpha-ApplicationHost"></a>

### ApplicationHost



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| processes | [ApplicationProcess](#application_model-v1alpha-ApplicationProcess) | repeated |  |






<a name="application_model-v1alpha-ApplicationModel"></a>

### ApplicationModel



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| namespaces | [ApplicationNamespace](#application_model-v1alpha-ApplicationNamespace) | repeated |  |
| host | [ApplicationHost](#application_model-v1alpha-ApplicationHost) |  |  |






<a name="application_model-v1alpha-ApplicationModelEvent"></a>

### ApplicationModelEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cluster_name | [string](#string) |  |  |
| node_name | [string](#string) |  |  |
| time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  |  |
| application_model | [ApplicationModel](#application_model-v1alpha-ApplicationModel) |  |  |






<a name="application_model-v1alpha-ApplicationNamespace"></a>

### ApplicationNamespace



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| workloads | [ApplicationWorkload](#application_model-v1alpha-ApplicationWorkload) | repeated |  |






<a name="application_model-v1alpha-ApplicationProcess"></a>

### ApplicationProcess



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hash | [string](#string) |  | Hash to identify this process in the process tree. |
| name | [string](#string) |  |  |
| arguments | [string](#string) |  | Arguments passed to this process. |
| children | [ApplicationProcess](#application_model-v1alpha-ApplicationProcess) | repeated | Child processes of this process. |
| connections | [ApplicationConnection](#application_model-v1alpha-ApplicationConnection) | repeated |  |






<a name="application_model-v1alpha-ApplicationWorkload"></a>

### ApplicationWorkload



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  |  |
| kind | [string](#string) |  |  |
| processes | [ApplicationProcess](#application_model-v1alpha-ApplicationProcess) | repeated |  |





 

 

 

 



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

