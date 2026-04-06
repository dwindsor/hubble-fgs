# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [l3l4networkpolicy/v1alpha/l3l4networkpolicy.proto](#l3l4networkpolicy_v1alpha_l3l4networkpolicy-proto)
    - [BasicAuth](#l3l4networkpolicy-v1alpha-BasicAuth)
    - [ConfigObject](#l3l4networkpolicy-v1alpha-ConfigObject)
    - [DpuConfig](#l3l4networkpolicy-v1alpha-DpuConfig)
    - [FlowExportConfig](#l3l4networkpolicy-v1alpha-FlowExportConfig)
    - [FlowExportConfigIpfix](#l3l4networkpolicy-v1alpha-FlowExportConfigIpfix)
    - [FlowExportConfigIpfix.ConfigsEntry](#l3l4networkpolicy-v1alpha-FlowExportConfigIpfix-ConfigsEntry)
    - [HAStatusEvent](#l3l4networkpolicy-v1alpha-HAStatusEvent)
    - [HaConfig](#l3l4networkpolicy-v1alpha-HaConfig)
    - [HaPeer](#l3l4networkpolicy-v1alpha-HaPeer)
    - [IssuerRef](#l3l4networkpolicy-v1alpha-IssuerRef)
    - [L3L4NetworkSubject](#l3l4networkpolicy-v1alpha-L3L4NetworkSubject)
    - [LogConfig](#l3l4networkpolicy-v1alpha-LogConfig)
    - [LogConfigSplunk](#l3l4networkpolicy-v1alpha-LogConfigSplunk)
    - [LogConfigSplunk.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigSplunk-ConfigsEntry)
    - [LogConfigSyslog](#l3l4networkpolicy-v1alpha-LogConfigSyslog)
    - [LogConfigSyslog.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigSyslog-ConfigsEntry)
    - [LogConfigTimescape](#l3l4networkpolicy-v1alpha-LogConfigTimescape)
    - [LogConfigTimescape.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigTimescape-ConfigsEntry)
    - [MTLSCertManager](#l3l4networkpolicy-v1alpha-MTLSCertManager)
    - [MTLSClientCA](#l3l4networkpolicy-v1alpha-MTLSClientCA)
    - [MTLSConfig](#l3l4networkpolicy-v1alpha-MTLSConfig)
    - [NetworkConfig](#l3l4networkpolicy-v1alpha-NetworkConfig)
    - [PolicyPorts](#l3l4networkpolicy-v1alpha-PolicyPorts)
    - [PolicyRule](#l3l4networkpolicy-v1alpha-PolicyRule)
    - [PolicyRuleEvent](#l3l4networkpolicy-v1alpha-PolicyRuleEvent)
    - [PolicySubject](#l3l4networkpolicy-v1alpha-PolicySubject)
    - [ReportStatus](#l3l4networkpolicy-v1alpha-ReportStatus)
    - [ReportStatusRequest](#l3l4networkpolicy-v1alpha-ReportStatusRequest)
    - [ReportStatusResponse](#l3l4networkpolicy-v1alpha-ReportStatusResponse)
    - [StreamDatapathConfigRequest](#l3l4networkpolicy-v1alpha-StreamDatapathConfigRequest)
    - [StreamDatapathConfigResponse](#l3l4networkpolicy-v1alpha-StreamDatapathConfigResponse)
    - [StreamEvent](#l3l4networkpolicy-v1alpha-StreamEvent)
    - [StreamEventsRequest](#l3l4networkpolicy-v1alpha-StreamEventsRequest)
    - [StreamEventsResponse](#l3l4networkpolicy-v1alpha-StreamEventsResponse)
    - [Streaml3l4NetworkPolicyRequest](#l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyRequest)
    - [Streaml3l4NetworkPolicyResponse](#l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyResponse)
    - [TimescapeConfig](#l3l4networkpolicy-v1alpha-TimescapeConfig)
    - [Token](#l3l4networkpolicy-v1alpha-Token)
    - [Vlan](#l3l4networkpolicy-v1alpha-Vlan)
    - [Vrf](#l3l4networkpolicy-v1alpha-Vrf)
  
    - [AgentType](#l3l4networkpolicy-v1alpha-AgentType)
    - [ConfigOperation](#l3l4networkpolicy-v1alpha-ConfigOperation)
    - [ConfigSource](#l3l4networkpolicy-v1alpha-ConfigSource)
    - [ConfigType](#l3l4networkpolicy-v1alpha-ConfigType)
    - [HAStatus](#l3l4networkpolicy-v1alpha-HAStatus)
    - [PolicyAction](#l3l4networkpolicy-v1alpha-PolicyAction)
    - [PolicyOperation](#l3l4networkpolicy-v1alpha-PolicyOperation)
    - [PolicyProtocol](#l3l4networkpolicy-v1alpha-PolicyProtocol)
    - [PolicyRuleError](#l3l4networkpolicy-v1alpha-PolicyRuleError)
  
    - [L3L4NetworkPolicyService](#l3l4networkpolicy-v1alpha-L3L4NetworkPolicyService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="l3l4networkpolicy_v1alpha_l3l4networkpolicy-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## l3l4networkpolicy/v1alpha/l3l4networkpolicy.proto



<a name="l3l4networkpolicy-v1alpha-BasicAuth"></a>

### BasicAuth
BasicAuth configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| username | [string](#string) |  | Username for BasicAuth |
| password | [string](#string) |  | Password for BasicAuth |






<a name="l3l4networkpolicy-v1alpha-ConfigObject"></a>

### ConfigObject
ConfigObject is a generic config object, which can be extended by adding additional configuration types


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| type | [ConfigType](#l3l4networkpolicy-v1alpha-ConfigType) |  | Type of the json encoded config, used to unmarshal the json object. |
| source | [ConfigSource](#l3l4networkpolicy-v1alpha-ConfigSource) |  | Source of the config, helpful when managing local and remote configurations. |
| config_dpu | [DpuConfig](#l3l4networkpolicy-v1alpha-DpuConfig) |  |  |
| config_log_syslog | [LogConfigSyslog](#l3l4networkpolicy-v1alpha-LogConfigSyslog) |  |  |
| config_flow_export_ipfix | [FlowExportConfigIpfix](#l3l4networkpolicy-v1alpha-FlowExportConfigIpfix) |  |  |
| config_log_timescape | [LogConfigTimescape](#l3l4networkpolicy-v1alpha-LogConfigTimescape) |  |  |
| config_log_splunk | [LogConfigSplunk](#l3l4networkpolicy-v1alpha-LogConfigSplunk) |  |  |
| config_ha | [HaConfig](#l3l4networkpolicy-v1alpha-HaConfig) |  |  |
| network_config | [NetworkConfig](#l3l4networkpolicy-v1alpha-NetworkConfig) |  |  |
| config_timescape | [TimescapeConfig](#l3l4networkpolicy-v1alpha-TimescapeConfig) |  |  |






<a name="l3l4networkpolicy-v1alpha-DpuConfig"></a>

### DpuConfig
Object to store NX configuration
CONFIG_TYPE_DPU


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| service_ip | [string](#string) |  | Service IP address of the switch |
| service_mac | [string](#string) |  | Service MAC address of the switch |
| port_low | [uint32](#uint32) |  | Low end of the port range assigned to this DPU |
| port_high | [uint32](#uint32) |  | High end of the port range assigned to this DPU |
| dpu_id | [uint32](#uint32) |  | Unique identifier for the DPU, the same as the DPU number (DPU1, etc.) |
| ha_ip | [string](#string) |  | **Deprecated.** DEPRECATED |
| serial_number | [string](#string) |  | Serial number of the switch |
| switch_name | [string](#string) |  | Name of the switch |






<a name="l3l4networkpolicy-v1alpha-FlowExportConfig"></a>

### FlowExportConfig
FlowExportConfig contains the configuration for a flow export collector.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Configuration id |
| name | [string](#string) |  | Configuration name |
| description | [string](#string) |  | Configuration description |
| host | [string](#string) |  | IPv4 only |






<a name="l3l4networkpolicy-v1alpha-FlowExportConfigIpfix"></a>

### FlowExportConfigIpfix
Object to store a list of ipfix flow export configuration
CONFIG_TYPE_FLOW_EXPORT_IPFIX = 9


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configs | [FlowExportConfigIpfix.ConfigsEntry](#l3l4networkpolicy-v1alpha-FlowExportConfigIpfix-ConfigsEntry) | repeated |  |






<a name="l3l4networkpolicy-v1alpha-FlowExportConfigIpfix-ConfigsEntry"></a>

### FlowExportConfigIpfix.ConfigsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [FlowExportConfig](#l3l4networkpolicy-v1alpha-FlowExportConfig) |  |  |






<a name="l3l4networkpolicy-v1alpha-HAStatusEvent"></a>

### HAStatusEvent



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| peer | [string](#string) |  | IP address for the peer |
| status | [HAStatus](#l3l4networkpolicy-v1alpha-HAStatus) |  | HA event status |
| status_message | [string](#string) |  | Optional string description of status |






<a name="l3l4networkpolicy-v1alpha-HaConfig"></a>

### HaConfig
Object to store HA configuration
CONFIG_TYPE_HA


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| peers | [HaPeer](#l3l4networkpolicy-v1alpha-HaPeer) | repeated | List of HA peers |
| enabled | [bool](#bool) |  | Enables HA, starts health checks with peers |
| flow_sync | [bool](#bool) |  | Starts synchronization of flows between peers |
| ha_ip | [string](#string) |  | Local HA IP address of the switch |






<a name="l3l4networkpolicy-v1alpha-HaPeer"></a>

### HaPeer



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ip | [string](#string) |  | IP address for the peer |
| min_port | [uint32](#uint32) |  | Minimum destination port of the peer |
| max_port | [uint32](#uint32) |  | Maximum destination port of the peer |






<a name="l3l4networkpolicy-v1alpha-IssuerRef"></a>

### IssuerRef
IssuerRef structure matching cert-manager format


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| group | [string](#string) |  | IssuerRef group (cert-manager.io) |
| kind | [string](#string) |  | Kubernetes kind (ClusterIssuer, Issuer) |
| name | [string](#string) |  | Issuer name |






<a name="l3l4networkpolicy-v1alpha-L3L4NetworkSubject"></a>

### L3L4NetworkSubject
L3Network subjects are endpoints (destination or source) that specify a L3 endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cidr | [string](#string) |  | CIDR of the subject, e.g. &#34;1.2.3.4/24&#34; |
| ports | [PolicyPorts](#l3l4networkpolicy-v1alpha-PolicyPorts) | repeated | Ports |
| vlan | [uint32](#uint32) |  | VLAN of the subject may be empty when unused |
| vrf | [string](#string) |  | VRF name of the subject may be empty when unused |
| vrf_id | [uint32](#uint32) |  | unique ID associated with the VRF Name. This is used by datapaths to encode the vrf name into packet headers. |






<a name="l3l4networkpolicy-v1alpha-LogConfig"></a>

### LogConfig
Object to store log export configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Configuration id |
| name | [string](#string) |  | Configuration name |
| description | [string](#string) |  | Configuration description |
| host | [string](#string) |  | IPv4 only |
| port | [string](#string) |  | Collector target port |
| protocol | [string](#string) |  | Protocol, only TCP or UDP |
| tls | [bool](#bool) |  | Turns TLS/HTTPS on or off |
| basic_auth | [BasicAuth](#l3l4networkpolicy-v1alpha-BasicAuth) |  | BasicAuth configuration |
| mtls | [MTLSConfig](#l3l4networkpolicy-v1alpha-MTLSConfig) |  | mTLS configuration |
| token | [Token](#l3l4networkpolicy-v1alpha-Token) |  | Token based configuration |






<a name="l3l4networkpolicy-v1alpha-LogConfigSplunk"></a>

### LogConfigSplunk
Object to store a list of splunk configuration
CONFIG_TYPE_LOG_SPLUNK


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configs | [LogConfigSplunk.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigSplunk-ConfigsEntry) | repeated |  |






<a name="l3l4networkpolicy-v1alpha-LogConfigSplunk-ConfigsEntry"></a>

### LogConfigSplunk.ConfigsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [LogConfig](#l3l4networkpolicy-v1alpha-LogConfig) |  |  |






<a name="l3l4networkpolicy-v1alpha-LogConfigSyslog"></a>

### LogConfigSyslog
Object to store a list of syslog configuration
CONFIG_TYPE_LOG_SYSLOG


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configs | [LogConfigSyslog.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigSyslog-ConfigsEntry) | repeated |  |






<a name="l3l4networkpolicy-v1alpha-LogConfigSyslog-ConfigsEntry"></a>

### LogConfigSyslog.ConfigsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [LogConfig](#l3l4networkpolicy-v1alpha-LogConfig) |  |  |






<a name="l3l4networkpolicy-v1alpha-LogConfigTimescape"></a>

### LogConfigTimescape
Object to store a list of timescape configuration
CONFIG_TYPE_LOG_TIMESCAPE


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| configs | [LogConfigTimescape.ConfigsEntry](#l3l4networkpolicy-v1alpha-LogConfigTimescape-ConfigsEntry) | repeated |  |






<a name="l3l4networkpolicy-v1alpha-LogConfigTimescape-ConfigsEntry"></a>

### LogConfigTimescape.ConfigsEntry



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| key | [string](#string) |  |  |
| value | [LogConfig](#l3l4networkpolicy-v1alpha-LogConfig) |  |  |






<a name="l3l4networkpolicy-v1alpha-MTLSCertManager"></a>

### MTLSCertManager
Kubernetes CertManager can support different issuers
  kind: ClusterIssuer
  kind: Issuer
The complete Signer string format is:
  &lt;plural-issuerRef.kind&gt;.&lt;issuerRef.group&gt;/&lt;issuerRef.name&gt;
Examples:
  - &#34;clusterissuers.cert-manager.io/cluster-root-ca-issuer&#34;
  - &#34;issuers.cert-manager.io/my-namespace-issuer&#34;


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| issuer_ref | [IssuerRef](#l3l4networkpolicy-v1alpha-IssuerRef) |  | Issuer reference |






<a name="l3l4networkpolicy-v1alpha-MTLSClientCA"></a>

### MTLSClientCA
Kubernetes CA (Certificate Authority) information
to get the ca.crt from Kubernetes Secret resource


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| secret_name | [string](#string) |  | CA Secret name |
| secret_namespace | [string](#string) |  | CA Secret namespace |






<a name="l3l4networkpolicy-v1alpha-MTLSConfig"></a>

### MTLSConfig
mTLS configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| enabled | [bool](#bool) |  | Enable mTLS |
| certmanager | [MTLSCertManager](#l3l4networkpolicy-v1alpha-MTLSCertManager) |  | Certificate manager configuration |
| managed_ca | [MTLSClientCA](#l3l4networkpolicy-v1alpha-MTLSClientCA) |  | Use cert-manager managed CA (reference to existing CA secret)

Future: Custom CA (provide your own CA cert/key) |






<a name="l3l4networkpolicy-v1alpha-NetworkConfig"></a>

### NetworkConfig
Object to store network configuration
CONFIG_TYPE_NETWORK


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| vlans | [Vlan](#l3l4networkpolicy-v1alpha-Vlan) | repeated | List of VLANs |
| vrfs | [Vrf](#l3l4networkpolicy-v1alpha-Vrf) | repeated | List of VRFs |






<a name="l3l4networkpolicy-v1alpha-PolicyPorts"></a>

### PolicyPorts



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| protocol | [PolicyProtocol](#l3l4networkpolicy-v1alpha-PolicyProtocol) |  | Protocol of the network subject, e.g. &#34;TCP&#34;, &#34;UDP&#34; |
| min_port | [uint32](#uint32) |  | Minimum port of the subject |
| max_port | [uint32](#uint32) |  | Maximum port of the subject |






<a name="l3l4networkpolicy-v1alpha-PolicyRule"></a>

### PolicyRule
Policy rule is the definition used to populate the datapath table either
Tetragon or smartswitch at the moment. Note a single policy may map to many
rules. These are intended to be easily mapped 1:1 by the specific backend
into a table based datastructures. For L3/L4 most obvious implementation is
an LPM.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| k8s_resource_version | [string](#string) |  | Kubernetes resource version of the corresponding Tetragon Network Policy resource |
| k8s_uid | [string](#string) |  | Kubernetes resource UID of the corresponding Tetragon Network Policy resource |
| policy_name | [string](#string) |  | Name of the policy that create the rule |
| rule_name | [string](#string) |  | The specific rule that created the rule |
| action | [PolicyAction](#l3l4networkpolicy-v1alpha-PolicyAction) |  | The verdict (action) to apply to any match |
| source | [PolicySubject](#l3l4networkpolicy-v1alpha-PolicySubject) |  | The source to apply the rule against. |
| destination | [PolicySubject](#l3l4networkpolicy-v1alpha-PolicySubject) |  | The destination to apply the rule against. |
| rule_index | [uint32](#uint32) |  | The specific rule index that created the rule |






<a name="l3l4networkpolicy-v1alpha-PolicyRuleEvent"></a>

### PolicyRuleEvent
PolicyRuleEvent represents an event related to a specific policy rule.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| rule_name | [string](#string) |  | Name of the specific rule |
| policy_name | [string](#string) |  | Name of the parent policy containing this rule |
| k8s_uid | [string](#string) |  | Kubernetes unique identifier (UID) of the policy |
| k8s_resource_version | [string](#string) |  | Kubernetes resource version of the policy |
| is_success | [bool](#bool) |  | True when policy is applied in dataplane successfully, false otherwise |
| error | [PolicyRuleError](#l3l4networkpolicy-v1alpha-PolicyRuleError) |  | Error type that occurred during policy rule processing Only relevant when is_success is false |
| error_message | [string](#string) |  | Optional string description of the error |






<a name="l3l4networkpolicy-v1alpha-PolicySubject"></a>

### PolicySubject
Policy Subjects are used for selectors, source, or destinations.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network | [L3L4NetworkSubject](#l3l4networkpolicy-v1alpha-L3L4NetworkSubject) |  | L3 Network specifier. |






<a name="l3l4networkpolicy-v1alpha-ReportStatus"></a>

### ReportStatus
Status event to report basic information about the agent and current policy
checksum.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_uid | [string](#string) |  | Node local UID of the agent, useful when multiple agents are colocated |
| dp_version | [string](#string) |  | Datapath version |
| agent_version | [string](#string) |  | Agent version |
| policy_checksum | [string](#string) |  | Checksum of the currently running policy |
| hostname | [string](#string) |  | Hostname of the system the agent running |
| architecture | [string](#string) |  | Architecture the agent is running on |
| os | [string](#string) |  | Operating system the agent is running on |
| type | [AgentType](#l3l4networkpolicy-v1alpha-AgentType) |  | Agent type |
| serial_number | [string](#string) |  | The Serial number of the hardware, useful for physical assets |
| mgmt_ip | [string](#string) |  | ManagementIP is the management IP address of this DPU |
| port_low | [uint32](#uint32) |  | PortLow is the low end of the port range assigned to this DPU |
| port_high | [uint32](#uint32) |  | PortHigh is the high end of the port range assigned to this DPU |
| hardware_model | [string](#string) |  | HardwareModel is the DPU hardware model |
| dpu_restarts | [uint32](#uint32) |  | DpuRestarts is the number of times the DPU has been restarted |
| last_dpu_restart | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | LastDpuRestart is the timestamp of the last time the DPU has been restarted |
| dataplane_restarts | [uint32](#uint32) |  | DataplaneRestarts is the number of times the Dataplane process has been restarted |
| last_dataplane_restart | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | LastDataplaneRestart is the timestamp of the last time the Dataplane process has been restarted |
| last_fwa_crash_time | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | LastFwaCrashTime is the timestamp of the last time the FWA has crashed |






<a name="l3l4networkpolicy-v1alpha-ReportStatusRequest"></a>

### ReportStatusRequest
Report status request.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| status | [ReportStatus](#l3l4networkpolicy-v1alpha-ReportStatus) |  |  |






<a name="l3l4networkpolicy-v1alpha-ReportStatusResponse"></a>

### ReportStatusResponse
Report status response.






<a name="l3l4networkpolicy-v1alpha-StreamDatapathConfigRequest"></a>

### StreamDatapathConfigRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_uid | [string](#string) |  |  |






<a name="l3l4networkpolicy-v1alpha-StreamDatapathConfigResponse"></a>

### StreamDatapathConfigResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| oper | [ConfigOperation](#l3l4networkpolicy-v1alpha-ConfigOperation) |  |  |
| config | [ConfigObject](#l3l4networkpolicy-v1alpha-ConfigObject) |  |  |






<a name="l3l4networkpolicy-v1alpha-StreamEvent"></a>

### StreamEvent
StreamEvent wraps different event types that can be streamed from the datapath.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_uid | [string](#string) |  | Agent UID |
| timestamp | [google.protobuf.Timestamp](#google-protobuf-Timestamp) |  | The time when the event occurred |
| rule | [PolicyRuleEvent](#l3l4networkpolicy-v1alpha-PolicyRuleEvent) |  | Policy rule event |
| ha_status | [HAStatusEvent](#l3l4networkpolicy-v1alpha-HAStatusEvent) |  | HA status event |






<a name="l3l4networkpolicy-v1alpha-StreamEventsRequest"></a>

### StreamEventsRequest
StreamEventsRequest is a client-to-server streaming message containing events to report.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| events | [StreamEvent](#l3l4networkpolicy-v1alpha-StreamEvent) | repeated | events is the list of stream events to report in this request. |






<a name="l3l4networkpolicy-v1alpha-StreamEventsResponse"></a>

### StreamEventsResponse







<a name="l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyRequest"></a>

### Streaml3l4NetworkPolicyRequest



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_uid | [string](#string) |  |  |






<a name="l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyResponse"></a>

### Streaml3l4NetworkPolicyResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| oper | [PolicyOperation](#l3l4networkpolicy-v1alpha-PolicyOperation) |  |  |
| policy | [PolicyRule](#l3l4networkpolicy-v1alpha-PolicyRule) |  |  |






<a name="l3l4networkpolicy-v1alpha-TimescapeConfig"></a>

### TimescapeConfig
Object to store Timescape client configuration
CONFIG_TYPE_TIMESCAPE


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [string](#string) |  | Configuration ID |
| name | [string](#string) |  | Configuration name |
| description | [string](#string) |  | Configuration description |
| host | [string](#string) |  | Timescape server host |
| port | [string](#string) |  | Timescape server port |
| protocol | [string](#string) |  | Protocol (TCP/UDP) |
| tls_enabled | [bool](#bool) |  | Enable TLS/HTTPS |
| endpoint_api | [string](#string) |  | Push API endpoint |
| max_retries | [uint32](#uint32) |  | Transport configuration for production deployments Maximum number of retry attempts for failed requests |
| connection_timeout_sec | [uint32](#uint32) |  | Connection establishment timeout in seconds |
| request_timeout_sec | [uint32](#uint32) |  | Request timeout in seconds |
| max_batch_size | [uint32](#uint32) |  | **Deprecated.** Deprecated: Batching configuration for message processing Maximum number of messages to batch together (default: 1, max: 3, recommended: 2) |
| batch_timeout_ms | [uint32](#uint32) |  | **Deprecated.** Batch timeout in milliseconds (force send batch after timeout, default: 30000ms) |
| basic_auth | [BasicAuth](#l3l4networkpolicy-v1alpha-BasicAuth) |  | BasicAuth configuration |
| mtls | [MTLSConfig](#l3l4networkpolicy-v1alpha-MTLSConfig) |  | mTLS configuration |
| policystatus_reporting_interval_mins | [uint32](#uint32) |  | Policy status reporting interval in minutes |






<a name="l3l4networkpolicy-v1alpha-Token"></a>

### Token
Token configuration


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| token | [string](#string) |  | Access token |






<a name="l3l4networkpolicy-v1alpha-Vlan"></a>

### Vlan



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  | VLAN id |
| name | [string](#string) |  | Optional VLAN name |






<a name="l3l4networkpolicy-v1alpha-Vrf"></a>

### Vrf



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | [uint32](#uint32) |  | VRF id, unique per switch |
| name | [string](#string) |  | VRF name |





 


<a name="l3l4networkpolicy-v1alpha-AgentType"></a>

### AgentType


| Name | Number | Description |
| ---- | ------ | ----------- |
| AGENT_TYPE_UNSPECIFIED | 0 | Agent type unspecified |
| AGENT_TYPE_DPU_AGW | 1 | Agent is AGW managing a DPU |
| AGENT_TYPE_TETRAGON | 2 | Agent is Tetragon |



<a name="l3l4networkpolicy-v1alpha-ConfigOperation"></a>

### ConfigOperation
Config operation is the instruction telling the backend what to do with a
ConfigObject.

| Name | Number | Description |
| ---- | ------ | ----------- |
| CONFIG_OPERATION_UNSPECIFIED | 0 | Unspecified or unknown operation |
| CONFIG_OPERATION_UPSERT | 1 | Add the associated config object. If the config object exists it should be replaced with the new object. |
| CONFIG_OPERATION_DELETE | 2 | Delete the associated config object. |



<a name="l3l4networkpolicy-v1alpha-ConfigSource"></a>

### ConfigSource


| Name | Number | Description |
| ---- | ------ | ----------- |
| CONFIG_SOURCE_UNSPECIFIED | 0 | Unspecified or unknown config source |
| CONFIG_SOURCE_LOCAL | 1 | Config from the local machine |
| CONFIG_SOURCE_CONFIGMAP | 2 | Config from the connected configmap |



<a name="l3l4networkpolicy-v1alpha-ConfigType"></a>

### ConfigType


| Name | Number | Description |
| ---- | ------ | ----------- |
| CONFIG_TYPE_UNSPECIFIED | 0 | Unspecified or unknown config type |
| CONFIG_TYPE_DPU | 1 | DPU configuration |
| CONFIG_TYPE_LOG_SYSLOG | 2 | Log export syslog configuration |
| CONFIG_TYPE_LOG_IPFIX | 3 | Deprecated: use CONFIG_TYPE_FLOW_EXPORT_IPFIX instead. |
| CONFIG_TYPE_LOG_TIMESCAPE | 4 | Log export timescape configuration |
| CONFIG_TYPE_LOG_SPLUNK | 5 | Log export splunk configuration |
| CONFIG_TYPE_HA | 6 | HA configuration |
| CONFIG_TYPE_NETWORK | 7 | Network configuration |
| CONFIG_TYPE_TIMESCAPE | 8 | Timescape ingestor configuration |
| CONFIG_TYPE_FLOW_EXPORT_IPFIX | 9 | Flow export IPFIX configuration |



<a name="l3l4networkpolicy-v1alpha-HAStatus"></a>

### HAStatus


| Name | Number | Description |
| ---- | ------ | ----------- |
| HA_STATUS_UNSPECIFIED | 0 | Unspecified or unknown HA status |
| HA_STATUS_KEEPALIVE_UP | 1 | HA peer connectivity up, keepalives working |
| HA_STATUS_KEEPALIVE_DOWN | 2 | HA peer connectivity down, keepalives failing |
| HA_STATUS_BULK_SYNC_DONE | 3 | HA bulk sync is finished sending to peer |
| HA_STATUS_BULK_SYNC_PEER_DONE | 4 | HA bulk sync is finished receiving from peer |



<a name="l3l4networkpolicy-v1alpha-PolicyAction"></a>

### PolicyAction
Policy action to apply when the rule is matched.

| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_ACTION_UNSPECIFIED | 0 | Unspecificied or unknown verdict. |
| POLICY_ACTION_ALLOW | 1 | Allow the packet or connection |
| POLICY_ACTION_DENY | 2 | Deny the packet or connection by blocking the connection or dropping the packet. |



<a name="l3l4networkpolicy-v1alpha-PolicyOperation"></a>

### PolicyOperation
Policy operation is the instruction telling the backeend what to do with a
PolicyRule.

| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_OPERATION_UNSPECIFIED | 0 | Unspecified or unknown operation |
| POLICY_OPERATION_UPSERT | 1 | Add the associated policy rule. If the policy exists it should be updated with any changes. |
| POLICY_OPERATION_DELETE | 2 | Delete the associated policy rule. |



<a name="l3l4networkpolicy-v1alpha-PolicyProtocol"></a>

### PolicyProtocol
Protocol number constants

| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_PROTOCOL_UNSPECIFIED | 0 | Unspecified or any protocol |
| POLICY_PROTOCOL_ICMP | 1 | ICMP protocol number |
| POLICY_PROTOCOL_TCP | 6 | TCP protocol number |
| POLICY_PROTOCOL_UDP | 17 | UDP protocol number |



<a name="l3l4networkpolicy-v1alpha-PolicyRuleError"></a>

### PolicyRuleError
PolicyRuleError enumerates error types that can occur during policy rule processing.

| Name | Number | Description |
| ---- | ------ | ----------- |
| POLICY_RULE_ERROR_UNSPECIFIED | 0 | No specific error, general catch all error |
| POLICY_RULE_ERROR_TIMEOUT | 1 | Policy operation timed out when sending to dataplane |
| POLICY_RULE_ERROR_OOM | 2 | Policy operation failed due to out-of-memory |
| POLICY_RULE_ERROR_UNSUPPORTED | 3 | Policy operation failed due to unsupported value, like an unsupported protocol in the rule |
| POLICY_RULE_ERROR_FORMAT | 4 | Policy operation failed due to invalid policy rule format |


 

 


<a name="l3l4networkpolicy-v1alpha-L3L4NetworkPolicyService"></a>

### L3L4NetworkPolicyService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Streaml3l4NetworkPolicy | [Streaml3l4NetworkPolicyRequest](#l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyRequest) | [Streaml3l4NetworkPolicyResponse](#l3l4networkpolicy-v1alpha-Streaml3l4NetworkPolicyResponse) stream |  |
| ReportStatus | [ReportStatusRequest](#l3l4networkpolicy-v1alpha-ReportStatusRequest) | [ReportStatusResponse](#l3l4networkpolicy-v1alpha-ReportStatusResponse) |  |
| StreamDatapathConfig | [StreamDatapathConfigRequest](#l3l4networkpolicy-v1alpha-StreamDatapathConfigRequest) | [StreamDatapathConfigResponse](#l3l4networkpolicy-v1alpha-StreamDatapathConfigResponse) stream |  |
| StreamEvents | [StreamEventsRequest](#l3l4networkpolicy-v1alpha-StreamEventsRequest) stream | [StreamEventsResponse](#l3l4networkpolicy-v1alpha-StreamEventsResponse) |  |

 



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

