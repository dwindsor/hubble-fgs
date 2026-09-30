# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [splunk/v1alpha/splunk.proto](#splunk_v1alpha_splunk-proto)
    - [GetHecSettingsRequest](#splunk-v1alpha-GetHecSettingsRequest)
    - [GetHecSettingsResponse](#splunk-v1alpha-GetHecSettingsResponse)
    - [SetHecSettingsRequest](#splunk-v1alpha-SetHecSettingsRequest)
    - [SetHecSettingsResponse](#splunk-v1alpha-SetHecSettingsResponse)
  
    - [SplunkService](#splunk-v1alpha-SplunkService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="splunk_v1alpha_splunk-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## splunk/v1alpha/splunk.proto



<a name="splunk-v1alpha-GetHecSettingsRequest"></a>

### GetHecSettingsRequest
Get hec settings takes no parameters






<a name="splunk-v1alpha-GetHecSettingsResponse"></a>

### GetHecSettingsResponse
Response contains endpoint, token, and source types


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| endpoint | [string](#string) |  | The HEC endpoint currently in use. If empty, HEC export is not enabled. |
| token | [string](#string) |  | The HEC token currently in use. |
| source_types | [string](#string) | repeated | The set of source types currently enabled. |






<a name="splunk-v1alpha-SetHecSettingsRequest"></a>

### SetHecSettingsRequest
Set endpoint to empty to disable sending to splunk


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| endpoint | [string](#string) |  | The HEC endpoint to use. If empty, disables HEC message forwarding. |
| token | [string](#string) |  | The HEC token to use. If endpoint is provided, token must be provided. |
| source_types | [string](#string) | repeated | The set of source types to use. May be empty when endpoint is provided. |






<a name="splunk-v1alpha-SetHecSettingsResponse"></a>

### SetHecSettingsResponse
The response is empty. All validation occurs client side so the settings
change always succeeds.





 

 

 


<a name="splunk-v1alpha-SplunkService"></a>

### SplunkService
This service is for interfacing with Splunk-related capabilities
within tetragon.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| GetHecSettings | [GetHecSettingsRequest](#splunk-v1alpha-GetHecSettingsRequest) | [GetHecSettingsResponse](#splunk-v1alpha-GetHecSettingsResponse) | Get current settings for Splunk HEC Export. |
| SetHecSettings | [SetHecSettingsRequest](#splunk-v1alpha-SetHecSettingsRequest) | [SetHecSettingsResponse](#splunk-v1alpha-SetHecSettingsResponse) | Update settings for Splunk HEC Export. |

 



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

