# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [ocsf/v1alpha/ocsf.proto](#ocsf_v1alpha_ocsf-proto)
    - [Account](#ocsf-v1alpha-Account)
    - [Actor](#ocsf-v1alpha-Actor)
    - [Agent](#ocsf-v1alpha-Agent)
    - [AuthenticationFactor](#ocsf-v1alpha-AuthenticationFactor)
    - [AuthorizationResult](#ocsf-v1alpha-AuthorizationResult)
    - [AutonomousSystem](#ocsf-v1alpha-AutonomousSystem)
    - [CVE](#ocsf-v1alpha-CVE)
    - [CVSSScore](#ocsf-v1alpha-CVSSScore)
    - [CWE](#ocsf-v1alpha-CWE)
    - [Device](#ocsf-v1alpha-Device)
    - [DeviceHardwareInfo](#ocsf-v1alpha-DeviceHardwareInfo)
    - [DigitalCertificate](#ocsf-v1alpha-DigitalCertificate)
    - [DigitalSignature](#ocsf-v1alpha-DigitalSignature)
    - [Display](#ocsf-v1alpha-Display)
    - [EPSS](#ocsf-v1alpha-EPSS)
    - [EncryptionDetails](#ocsf-v1alpha-EncryptionDetails)
    - [Enrichment](#ocsf-v1alpha-Enrichment)
    - [EnvironmentVariable](#ocsf-v1alpha-EnvironmentVariable)
    - [Feature](#ocsf-v1alpha-Feature)
    - [File](#ocsf-v1alpha-File)
    - [Fingerprint](#ocsf-v1alpha-Fingerprint)
    - [FirewallRule](#ocsf-v1alpha-FirewallRule)
    - [GeoLocation](#ocsf-v1alpha-GeoLocation)
    - [Group](#ocsf-v1alpha-Group)
    - [IdentityProvider](#ocsf-v1alpha-IdentityProvider)
    - [Image](#ocsf-v1alpha-Image)
    - [JA4Fingerprint](#ocsf-v1alpha-JA4Fingerprint)
    - [KeyValueobject](#ocsf-v1alpha-KeyValueobject)
    - [KeyboardInformation](#ocsf-v1alpha-KeyboardInformation)
    - [LDAPPerson](#ocsf-v1alpha-LDAPPerson)
    - [Logger](#ocsf-v1alpha-Logger)
    - [MITREATTCK](#ocsf-v1alpha-MITREATTCK)
    - [MITREATTCKSubTechnique](#ocsf-v1alpha-MITREATTCKSubTechnique)
    - [MITREATTCKTactic](#ocsf-v1alpha-MITREATTCKTactic)
    - [MITREATTCKTechnique](#ocsf-v1alpha-MITREATTCKTechnique)
    - [Malware](#ocsf-v1alpha-Malware)
    - [Metadata](#ocsf-v1alpha-Metadata)
    - [Metric](#ocsf-v1alpha-Metric)
    - [NetworkActivity](#ocsf-v1alpha-NetworkActivity)
    - [NetworkConnectionInformation](#ocsf-v1alpha-NetworkConnectionInformation)
    - [NetworkEndpoint](#ocsf-v1alpha-NetworkEndpoint)
    - [NetworkInterface](#ocsf-v1alpha-NetworkInterface)
    - [NetworkProxyEndpoint](#ocsf-v1alpha-NetworkProxyEndpoint)
    - [NetworkTraffic](#ocsf-v1alpha-NetworkTraffic)
    - [Object](#ocsf-v1alpha-Object)
    - [Observable](#ocsf-v1alpha-Observable)
    - [OperatingSystemOS](#ocsf-v1alpha-OperatingSystemOS)
    - [Organization](#ocsf-v1alpha-Organization)
    - [Policy](#ocsf-v1alpha-Policy)
    - [Process](#ocsf-v1alpha-Process)
    - [ProcessEntity](#ocsf-v1alpha-ProcessEntity)
    - [Product](#ocsf-v1alpha-Product)
    - [Reputation](#ocsf-v1alpha-Reputation)
    - [SCIM](#ocsf-v1alpha-SCIM)
    - [SSO](#ocsf-v1alpha-SSO)
    - [SchemaExtension](#ocsf-v1alpha-SchemaExtension)
    - [Session](#ocsf-v1alpha-Session)
    - [SubjectAlternativeName](#ocsf-v1alpha-SubjectAlternativeName)
    - [TLSExtension](#ocsf-v1alpha-TLSExtension)
    - [TransportLayerSecurityTLS](#ocsf-v1alpha-TransportLayerSecurityTLS)
    - [UniformResourceLocator](#ocsf-v1alpha-UniformResourceLocator)
    - [User](#ocsf-v1alpha-User)
  
    - [AccountTypeID](#ocsf-v1alpha-AccountTypeID)
    - [AgentTypeID](#ocsf-v1alpha-AgentTypeID)
    - [AuthenticationFactorFactorTypeID](#ocsf-v1alpha-AuthenticationFactorFactorTypeID)
    - [BaseEventSeverityID](#ocsf-v1alpha-BaseEventSeverityID)
    - [BaseEventStatusID](#ocsf-v1alpha-BaseEventStatusID)
    - [CategoryID](#ocsf-v1alpha-CategoryID)
    - [ClassID](#ocsf-v1alpha-ClassID)
    - [DeviceHardwareInfoCPUArchitectureID](#ocsf-v1alpha-DeviceHardwareInfoCPUArchitectureID)
    - [DeviceRiskLevelID](#ocsf-v1alpha-DeviceRiskLevelID)
    - [DeviceTypeID](#ocsf-v1alpha-DeviceTypeID)
    - [DigitalSignatureAlgorithmID](#ocsf-v1alpha-DigitalSignatureAlgorithmID)
    - [DigitalSignatureStateID](#ocsf-v1alpha-DigitalSignatureStateID)
    - [EncryptionDetailsAlgorithmID](#ocsf-v1alpha-EncryptionDetailsAlgorithmID)
    - [FileConfidentialityID](#ocsf-v1alpha-FileConfidentialityID)
    - [FileDriveTypeID](#ocsf-v1alpha-FileDriveTypeID)
    - [FileTypeID](#ocsf-v1alpha-FileTypeID)
    - [FingerprintAlgorithmID](#ocsf-v1alpha-FingerprintAlgorithmID)
    - [IdentityProviderStateID](#ocsf-v1alpha-IdentityProviderStateID)
    - [JA4FingerprintTypeID](#ocsf-v1alpha-JA4FingerprintTypeID)
    - [MalwareClassificationIDs](#ocsf-v1alpha-MalwareClassificationIDs)
    - [NetworkActivityActivityID](#ocsf-v1alpha-NetworkActivityActivityID)
    - [NetworkConnectionInformationBoundaryID](#ocsf-v1alpha-NetworkConnectionInformationBoundaryID)
    - [NetworkConnectionInformationDirectionID](#ocsf-v1alpha-NetworkConnectionInformationDirectionID)
    - [NetworkConnectionInformationProtocolVersionID](#ocsf-v1alpha-NetworkConnectionInformationProtocolVersionID)
    - [NetworkEndpointTypeID](#ocsf-v1alpha-NetworkEndpointTypeID)
    - [NetworkInterfaceTypeID](#ocsf-v1alpha-NetworkInterfaceTypeID)
    - [ObservableTypeID](#ocsf-v1alpha-ObservableTypeID)
    - [OperatingSystemOSTypeID](#ocsf-v1alpha-OperatingSystemOSTypeID)
    - [ProcessIntegrityLevel](#ocsf-v1alpha-ProcessIntegrityLevel)
    - [ReputationReputationScoreID](#ocsf-v1alpha-ReputationReputationScoreID)
    - [SCIMAuthProtocolID](#ocsf-v1alpha-SCIMAuthProtocolID)
    - [SCIMStateID](#ocsf-v1alpha-SCIMStateID)
    - [SSOAuthProtocolID](#ocsf-v1alpha-SSOAuthProtocolID)
    - [SecurityControlActionID](#ocsf-v1alpha-SecurityControlActionID)
    - [SecurityControlConfidenceID](#ocsf-v1alpha-SecurityControlConfidenceID)
    - [SecurityControlDispositionID](#ocsf-v1alpha-SecurityControlDispositionID)
    - [SecurityControlRiskLevelID](#ocsf-v1alpha-SecurityControlRiskLevelID)
    - [TLSExtensionTypeID](#ocsf-v1alpha-TLSExtensionTypeID)
    - [UniformResourceLocatorWebsiteCategorizationIDs](#ocsf-v1alpha-UniformResourceLocatorWebsiteCategorizationIDs)
    - [UserRiskLevelID](#ocsf-v1alpha-UserRiskLevelID)
    - [UserTypeID](#ocsf-v1alpha-UserTypeID)
  
- [ocsf/v1alpha/cisco.proto](#ocsf_v1alpha_cisco-proto)
    - [EndpointEvent](#ocsf-v1alpha-EndpointEvent)
  
- [ocsf/v1alpha/grpc.proto](#ocsf_v1alpha_grpc-proto)
    - [StreamOCSFRequest](#ocsf-v1alpha-StreamOCSFRequest)
    - [StreamOCSFResponse](#ocsf-v1alpha-StreamOCSFResponse)
  
    - [OCSFService](#ocsf-v1alpha-OCSFService)
  
- [Scalar Value Types](#scalar-value-types)



<a name="ocsf_v1alpha_ocsf-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## ocsf/v1alpha/ocsf.proto
PROTOBUF SCHEMA

Autogenerated from OCSF v1.4.0 at 16:38:25 on 2025-05-19. DO NOT EDIT.

Event specified for this invocation:
- network_activity

Profiles specified for this invocation:
- datetime
- host
- linux/linux_users
- security_control

Extension specified for this invocation:
- linux

Please contact Dave McCormack (dmccorma@cisco.com) with bugs, etc.


<a name="ocsf-v1alpha-Account"></a>

### Account
The Account object contains details about the account that initiated or
performed a specific activity within a system or application. Additionally,
the Account object refers to logical Cloud and Software-as-a-Service (SaaS)
based containers such as AWS Accounts, Azure Subscriptions, Oracle Cloud
Compartments, Google Cloud Projects, and otherwise.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| labels | [string](#string) | repeated | Description: The list of labels associated to the account.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the account (e.g. GCP Project name , Linux Account name or AWS Account name).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| tags | [KeyValueobject](#ocsf-v1alpha-KeyValueobject) | repeated | Description: The list of tags; {key:value} pairs associated to the account.

Data Type: A message field of type KeyValueobject.

Requirement: optional |
| type | [string](#string) | optional | Description: The account type, normalized to the caption of &#39;account_type_id&#39;. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [AccountTypeID](#ocsf-v1alpha-AccountTypeID) | optional | Description: The normalized account type identifier.

Data Type: An enum field of type AccountTypeID.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The unique identifier of the account (e.g. AWS Account ID , OCID , GCP Project ID , Azure Subscription ID , Google Workspace Customer ID , or M365 Tenant UID).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Actor"></a>

### Actor
The Actor object contains details about the user, role, application, service,
or process that initiated or performed a specific activity. Note that Actor
is not the threat actor of a campaign but may be part of a campaign.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| app_name | [string](#string) | optional | Description: The client application or service that initiated the activity. This can be in conjunction with the user if present. Note that app_name is distinct from the process if present.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| app_uid | [string](#string) | optional | Description: The unique identifier of the client application or service that initiated the activity. This can be in conjunction with the user if present. Note that app_name is distinct from the process.pid or process.uid if present.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| authorizations | [AuthorizationResult](#ocsf-v1alpha-AuthorizationResult) | repeated | Description: Provides details about an authorization, such as authorization outcome, and any associated policies related to the activity/event.

Data Type: A message field of type AuthorizationResult.

Requirement: optional |
| idp | [IdentityProvider](#ocsf-v1alpha-IdentityProvider) | optional | Description: This object describes details about the Identity Provider used.

Data Type: A message field of type IdentityProvider.

Requirement: optional |
| invoked_by | [string](#string) | optional | Description: The name of the service that invoked the activity as described in the event.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| process | [Process](#ocsf-v1alpha-Process) | optional | Description: The process that initiated the activity.

Data Type: A message field of type Process.

Requirement: recommended |
| session | [Session](#ocsf-v1alpha-Session) | optional | Description: The user session from which the activity was initiated.

Data Type: A message field of type Session.

Requirement: optional |
| user | [User](#ocsf-v1alpha-User) | optional | Description: The user that initiated the activity or the user context from which the activity was initiated.

Data Type: A message field of type User.

Requirement: recommended |






<a name="ocsf-v1alpha-Agent"></a>

### Agent
An Agent (also known as a Sensor) is typically installed on an Operating
System (OS) and serves as a specialized software component that can be
designed to monitor, detect, collect, archive, or take action. These
activities and possible actions are defined by the upstream system
controlling the Agent and its intended purpose. For instance, an Agent can
include Endpoint Detection &amp; Response (EDR) agents, backup/disaster recovery
sensors, Application Performance Monitoring or profiling sensors, and similar
software.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The name of the agent or sensor. For example: AWS SSM Agent.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| policies | [Policy](#ocsf-v1alpha-Policy) | repeated | Description: Describes the various policies that may be applied or enforced by an agent or sensor. E.g., Conditional Access, prevention, auto-update, tamper protection, destination configuration, etc.

Data Type: A message field of type Policy.

Requirement: optional |
| type | [string](#string) | optional | Description: The normalized caption of the type_id value for the agent or sensor. In the case of &#39;Other&#39; or &#39;Unknown&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [AgentTypeID](#ocsf-v1alpha-AgentTypeID) | optional | Description: The normalized representation of an agent or sensor. E.g., EDR, vulnerability management, APM, backup &amp; recovery, etc.

Data Type: An enum field of type AgentTypeID.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The UID of the agent or sensor, sometimes known as a Sensor ID or aid.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid_alt | [string](#string) | optional | Description: An alternative or contextual identifier for the agent or sensor, such as a configuration, organization, or license UID.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: The company or author who created the agent or sensor. For example: Crowdstrike.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: The semantic version of the agent or sensor, e.g., 7.101.50.0.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-AuthenticationFactor"></a>

### AuthenticationFactor
An Authentication Factor object describes a category of methods used for
identity verification in an authentication attempt.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| device | [Device](#ocsf-v1alpha-Device) | optional | Description: Device used to complete an authentication request.

Data Type: A message field of type Device.

Requirement: recommended |
| email_addr | [string](#string) | optional | Description: The email address used in an email-based authentication factor.

Data Type: Email address. For example:john_doe@example.com.

Requirement: optional |
| factor_type | [string](#string) | optional | Description: The type of authentication factor used in an authentication attempt.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| factor_type_id | [AuthenticationFactorFactorTypeID](#ocsf-v1alpha-AuthenticationFactorFactorTypeID) |  | Description: The normalized identifier for the authentication factor.

Data Type: An enum field of type AuthenticationFactorFactorTypeID.

Requirement: required |
| is_hotp | [bool](#bool) | optional | Description: Whether the authentication factor is an HMAC-based One-time Password (HOTP).

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| is_totp | [bool](#bool) | optional | Description: Whether the authentication factor is a Time-based One-time Password (TOTP).

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| phone_number | [string](#string) | optional | Description: The phone number used for a telephony-based authentication request.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| provider | [string](#string) | optional | Description: The name of provider for an authentication factor.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| security_questions | [string](#string) | repeated | Description: The question(s) provided to user for a question-based authentication factor.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-AuthorizationResult"></a>

### AuthorizationResult
The Authorization Result object provides details about the authorization
outcome and associated policies related to activity.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| decision | [string](#string) | optional | Description: Authorization Result/outcome, e.g. allowed, denied.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| policy | [Policy](#ocsf-v1alpha-Policy) | optional | Description: Details about the Identity/Access management policies that are applicable.

Data Type: A message field of type Policy.

Requirement: optional |






<a name="ocsf-v1alpha-AutonomousSystem"></a>

### AutonomousSystem
An autonomous system (AS) is a collection of connected Internet Protocol (IP)
routing prefixes under the control of one or more network operators on behalf
of a single administrative entity or domain that presents a common, clearly
defined routing policy to the internet.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: Organization name for the Autonomous System.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| number | [int32](#int32) | optional | Description: Unique number that the AS is identified by.

Data Type: Signed integer value.

Requirement: recommended |






<a name="ocsf-v1alpha-CVE"></a>

### CVE
The Common Vulnerabilities and Exposures (CVE) object represents publicly
disclosed cybersecurity vulnerabilities defined in CVE Program catalog (CVE).
There is one CVE Record for each vulnerability in the catalog.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| created_time | [int64](#int64) | optional | Description: The Record Creation Date identifies when the CVE ID was issued to a CVE Numbering Authority (CNA) or the CVE Record was published on the CVE List. Note that the Record Creation Date does not necessarily indicate when this vulnerability was discovered, shared with the affected vendor, publicly disclosed, or updated in CVE.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The Record Creation Date identifies when the CVE ID was issued to a CVE Numbering Authority (CNA) or the CVE Record was published on the CVE List. Note that the Record Creation Date does not necessarily indicate when this vulnerability was discovered, shared with the affected vendor, publicly disclosed, or updated in CVE.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| cvss | [CVSSScore](#ocsf-v1alpha-CVSSScore) | repeated | Description: The CVSS object details Common Vulnerability Scoring System (CVSS) scores from the advisory that are related to the vulnerability.

Data Type: A message field of type CVSSScore.

Requirement: recommended |
| cwe | [CWE](#ocsf-v1alpha-CWE) | optional | Description: The CWE object represents a weakness in a software system that can be exploited by a threat actor to perform an attack. The CWE object is based on the Common Weakness Enumeration (CWE) catalog.

Data Type: A message field of type CWE.

Requirement: optional |
| cwe_uid | [string](#string) | optional | Description: The Common Weakness Enumeration (CWE) unique identifier. For example: CWE-787.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cwe_url | [string](#string) | optional | Description: Common Weakness Enumeration (CWE) definition URL. For example: https://cwe.mitre.org/data/definitions/787.html.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| desc | [string](#string) | optional | Description: A brief description of the CVE Record.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| epss | [EPSS](#ocsf-v1alpha-EPSS) | optional | Description: The Exploit Prediction Scoring System (EPSS) object describes the estimated probability a vulnerability will be exploited. EPSS is a community-driven effort to combine descriptive information about vulnerabilities (CVEs) with evidence of actual exploitation in-the-wild. (EPSS).

Data Type: A message field of type EPSS.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The Record Modified Date identifies when the CVE record was last updated.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The Record Modified Date identifies when the CVE record was last updated.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| product | [Product](#ocsf-v1alpha-Product) | optional | Description: The product where the vulnerability was discovered.

Data Type: A message field of type Product.

Requirement: optional |
| references | [string](#string) | repeated | Description: A list of reference URLs with additional information about the CVE Record.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| related_cwes | [CWE](#ocsf-v1alpha-CWE) | repeated | Description: Describes the Common Weakness Enumeration (CWE) details related to the CVE Record.

Data Type: A message field of type CWE.

Requirement: optional |
| title | [string](#string) | optional | Description: A title or a brief phrase summarizing the CVE record.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| type | [string](#string) | optional | Description: The vulnerability type as selected from a large dropdown menu during CVE refinement.Most frequently used vulnerability types are: DoS, Code Execution, Overflow, Memory Corruption, Sql Injection, XSS, Directory Traversal, Http Response Splitting, Bypass something, Gain Information, Gain Privileges, CSRF, File Inclusion. For more information see Vulnerabilities By Type distributions.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid | [string](#string) |  | Description: The Common Vulnerabilities and Exposures unique number assigned to a specific computer vulnerability. A CVE Identifier begins with 4 digits representing the year followed by a sequence of digits that acts as a unique identifier. For example: CVE-2021-12345.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-CVSSScore"></a>

### CVSSScore
The Common Vulnerability Scoring System (CVSS) object provides a way to
capture the principal characteristics of a vulnerability and produce a
numerical score reflecting its severity.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base_score | [float](#float) |  | Description: The CVSS base score. For example: 9.1.

Data Type: Real floating-point value. For example:3.14.

Requirement: required |
| depth | [string](#string) | optional | Description: The CVSS depth represents a depth of the equation used to calculate CVSS score.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| metrics | [Metric](#ocsf-v1alpha-Metric) | repeated | Description: The Common Vulnerability Scoring System metrics. This attribute contains information on the CVE&#39;s impact. If the CVE has been analyzed, this attribute will contain any CVSSv2 or CVSSv3 information associated with the vulnerability. For example: { {&#34;Access Vector&#34;, &#34;Network&#34;}, {&#34;Access Complexity&#34;, &#34;Low&#34;}, ...}.

Data Type: A message field of type Metric.

Requirement: optional |
| overall_score | [float](#float) | optional | Description: The CVSS overall score, impacted by base, temporal, and environmental metrics. For example: 9.1.

Data Type: Real floating-point value. For example:3.14.

Requirement: recommended |
| severity | [string](#string) | optional | Description: The Common Vulnerability Scoring System (CVSS) Qualitative Severity Rating. A textual representation of the numeric score.CVSS v2.0Low (0.0  3.9)Medium (4.0  6.9)High (7.0  10.0)CVSS v3.0None (0.0)Low (0.1 - 3.9)Medium (4.0 - 6.9)High (7.0 - 8.9)Critical (9.0 - 10.0)

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| src_url | [string](#string) | optional | Description: The source URL for the CVSS score. For example: https://nvd.nist.gov/vuln/detail/CVE-2021-44228

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| vector_string | [string](#string) | optional | Description: The CVSS vector string is a text representation of a set of CVSS metrics. It is commonly used to record or transfer CVSS metric information in a concise form. For example: 3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: The vendor that provided the CVSS score. For example: NVD, REDHAT etc.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| version | [string](#string) |  | Description: The CVSS version. For example: 3.1.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-CWE"></a>

### CWE
The CWE object represents a weakness in a software system that can be
exploited by a threat actor to perform an attack. The CWE object is based on
the Common Weakness Enumeration (CWE) catalog.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| caption | [string](#string) | optional | Description: The caption assigned to the Common Weakness Enumeration unique identifier.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| src_url | [string](#string) | optional | Description: URL pointing to the CWE Specification. For more information see CWE.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| uid | [string](#string) |  | Description: The Common Weakness Enumeration unique number assigned to a specific weakness. A CWE Identifier begins &#34;CWE&#34; followed by a sequence of digits that acts as a unique identifier. For example: CWE-123.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-Device"></a>

### Device
The Device object represents an addressable computer system or host, which is
typically connected to a computer network and participates in the
transmission or processing of data within the computer network.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_list | [Agent](#ocsf-v1alpha-Agent) | repeated | Description: A list of agent objects associated with a device, endpoint, or resource.

Data Type: A message field of type Agent.

Requirement: optional |
| autoscale_uid | [string](#string) | optional | Description: The unique identifier of the cloud autoscale configuration.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| boot_time | [int64](#int64) | optional | Description: The time the system was booted.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| boot_time_dt | [string](#string) | optional | Description: The time the system was booted.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| created_time | [int64](#int64) | optional | Description: The time when the device was known to have been created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: The time when the device was known to have been created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| desc | [string](#string) | optional | Description: The description of the device, ordinarily as reported by the operating system.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| domain | [string](#string) | optional | Description: The network domain where the device resides. For example: work.example.com.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| first_seen_time | [int64](#int64) | optional | Description: The initial discovery time of the device.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| first_seen_time_dt | [string](#string) | optional | Description: The initial discovery time of the device.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| groups | [Group](#ocsf-v1alpha-Group) | repeated | Description: The group names to which the device belongs. For example: [&#34;Windows Laptops&#34;, &#34;Engineering&#34;].

Data Type: A message field of type Group.

Requirement: optional |
| hostname | [string](#string) | optional | Description: The device hostname.

Data Type: Unique name assigned to a device connected to a computer network. It may be a fully qualified domain name (FQDN). For example:r2-d2.example.com.,mx.example.com

Requirement: recommended |
| hw_info | [DeviceHardwareInfo](#ocsf-v1alpha-DeviceHardwareInfo) | optional | Description: The endpoint hardware information.

Data Type: A message field of type DeviceHardwareInfo.

Requirement: optional |
| hypervisor | [string](#string) | optional | Description: The name of the hypervisor running on the device. For example, Xen, VMware, Hyper-V, VirtualBox, etc.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| image | [Image](#ocsf-v1alpha-Image) | optional | Description: The image used as a template to run the virtual machine.

Data Type: A message field of type Image.

Requirement: optional |
| imei | [string](#string) | optional | Description: The International Mobile Equipment Identity that is associated with the device.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| imei_list | [string](#string) | repeated | Description: The International Mobile Equipment Identity values that are associated with the device.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| instance_uid | [string](#string) | optional | Description: The unique identifier of a VM instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_name | [string](#string) | optional | Description: The name of the network interface (e.g. eth2).

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_uid | [string](#string) | optional | Description: The unique identifier of the network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| ip | [string](#string) | optional | Description: The device IP address, in either IPv4 or IPv6 format.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: optional |
| is_compliant | [bool](#bool) | optional | Description: The event occurred on a compliant device.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_managed | [bool](#bool) | optional | Description: The event occurred on a managed device.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_personal | [bool](#bool) | optional | Description: The event occurred on a personal device.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_trusted | [bool](#bool) | optional | Description: The event occurred on a trusted device.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| last_seen_time | [int64](#int64) | optional | Description: The most recent discovery time of the device.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| last_seen_time_dt | [string](#string) | optional | Description: The most recent discovery time of the device.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| location | [GeoLocation](#ocsf-v1alpha-GeoLocation) | optional | Description: The geographical location of the device.

Data Type: A message field of type GeoLocation.

Requirement: optional |
| mac | [string](#string) | optional | Description: The Media Access Control (MAC) address of the endpoint.

Data Type: Media Access Control (MAC) address. For example:18:36:F3:98:4F:9A.

Requirement: optional |
| model | [string](#string) | optional | Description: The model of the device. For example ThinkPad X1 Carbon.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The time when the device was last known to have been modified.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The time when the device was last known to have been modified.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| name | [string](#string) | optional | Description: The alternate device name, ordinarily as assigned by an administrator. Note: The Name could be any other string that helps to identify the device, such as a phone number; for example 310-555-1234.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| network_interfaces | [NetworkInterface](#ocsf-v1alpha-NetworkInterface) | repeated | Description: The network interfaces that are associated with the device, one for each unique MAC address/IP address/hostname/name combination.Note: The first element of the array is the network information that pertains to the event.

Data Type: A message field of type NetworkInterface.

Requirement: optional |
| org | [Organization](#ocsf-v1alpha-Organization) | optional | Description: Organization and org unit related to the device.

Data Type: A message field of type Organization.

Requirement: optional |
| os | [OperatingSystemOS](#ocsf-v1alpha-OperatingSystemOS) | optional | Description: The endpoint operating system.

Data Type: A message field of type OperatingSystemOS.

Requirement: optional |
| os_machine_uuid | [string](#string) | optional | Description: The operating system assigned Machine ID. In Windows, this is the value stored at the registry path: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid. In Linux, this is stored in the file: /etc/machine-id.

Data Type: 128-bit universal unique identifier. For example:123e4567-e89b-12d3-a456-42661417400.

Requirement: optional |
| owner | [User](#ocsf-v1alpha-User) | optional | Description: The identity of the service or user account that owns the endpoint or was last logged into it.

Data Type: A message field of type User.

Requirement: recommended |
| region | [string](#string) | optional | Description: The region where the virtual machine is located. For example, an AWS Region.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| risk_level | [string](#string) | optional | Description: The risk level, normalized to the caption of the risk_level_id value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_level_id | [DeviceRiskLevelID](#ocsf-v1alpha-DeviceRiskLevelID) | optional | Description: The normalized risk level id.

Data Type: An enum field of type DeviceRiskLevelID.

Requirement: optional |
| risk_score | [int32](#int32) | optional | Description: The risk score as reported by the event source.

Data Type: Signed integer value.

Requirement: optional |
| subnet | [string](#string) | optional | Description: The subnet mask.

Data Type: The subnet represented in a CIDR notation, using the format network_address/prefix_length. The network_address can be in either IPv4 or IPv6 format. The prefix length indicates the number of bits used for the network portion, and the remaining bits are available for host addresses within that subnet. For example:192.168.1.0/24,2001:0db8:85a3:0000::/64

Requirement: optional |
| subnet_uid | [string](#string) | optional | Description: The unique identifier of a virtual subnet.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type | [string](#string) | optional | Description: The device type. For example: unknown, server, desktop, laptop, tablet, mobile, virtual, browser, or other.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| type_id | [DeviceTypeID](#ocsf-v1alpha-DeviceTypeID) |  | Description: The device type ID.

Data Type: An enum field of type DeviceTypeID.

Requirement: required |
| uid | [string](#string) | optional | Description: The unique identifier of the device. For example the Windows TargetSID or AWS EC2 ARN.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid_alt | [string](#string) | optional | Description: An alternate unique identifier of the device if any. For example the ActiveDirectory DN.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: The vendor for the device. For example Dell or Lenovo.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| vlan_uid | [string](#string) | optional | Description: The Virtual LAN identifier.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vpc_uid | [string](#string) | optional | Description: The unique identifier of the Virtual Private Cloud (VPC).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| zone | [string](#string) | optional | Description: The network zone or LAN segment.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-DeviceHardwareInfo"></a>

### DeviceHardwareInfo
The Device Hardware Information object contains details and specifications of
the physical components that make up a device. This information provides an
overview of the hardware capabilities, configuration, and characteristics of
the device.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bios_date | [string](#string) | optional | Description: The BIOS date. For example: 03/31/16.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| bios_manufacturer | [string](#string) | optional | Description: The BIOS manufacturer. For example: LENOVO.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| bios_ver | [string](#string) | optional | Description: The BIOS version. For example: LENOVO G5ETA2WW (2.62).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| chassis | [string](#string) | optional | Description: The chassis type describes the system enclosure or physical form factor. Such as the following examples for Windows Windows Chassis Types

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cpu_architecture | [string](#string) | optional | Description: The CPU architecture, normalized to the caption of the cpu_architecture_id value. In the case of Other, it is defined by the source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cpu_architecture_id | [DeviceHardwareInfoCPUArchitectureID](#ocsf-v1alpha-DeviceHardwareInfoCPUArchitectureID) | optional | Description: The normalized identifier of the CPU architecture.

Data Type: An enum field of type DeviceHardwareInfoCPUArchitectureID.

Requirement: optional |
| cpu_bits | [int32](#int32) | optional | Description: The cpu architecture, the number of bits used for addressing in memory. For example: 32 or 64.

Data Type: Signed integer value.

Requirement: optional |
| cpu_cores | [int32](#int32) | optional | Description: The number of processor cores in all installed processors. For Example: 42.

Data Type: Signed integer value.

Requirement: optional |
| cpu_count | [int32](#int32) | optional | Description: The number of physical processors on a system. For example: 1.

Data Type: Signed integer value.

Requirement: optional |
| cpu_speed | [int32](#int32) | optional | Description: The speed of the processor in Mhz. For Example: 4200.

Data Type: Signed integer value.

Requirement: optional |
| cpu_type | [string](#string) | optional | Description: The processor type. For example: x86 Family 6 Model 37 Stepping 5.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| desktop_display | [Display](#ocsf-v1alpha-Display) | optional | Description: The desktop display affiliated with the event

Data Type: A message field of type Display.

Requirement: optional |
| keyboard_info | [KeyboardInformation](#ocsf-v1alpha-KeyboardInformation) | optional | Description: The keyboard detailed information.

Data Type: A message field of type KeyboardInformation.

Requirement: optional |
| ram_size | [int32](#int32) | optional | Description: The total amount of installed RAM, in Megabytes. For example: 2048.

Data Type: Signed integer value.

Requirement: optional |
| serial_number | [string](#string) | optional | Description: The device manufacturer serial number.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uuid | [string](#string) | optional | Description: The device manufacturer assigned universally unique hardware identifier. For example: The BIOS System UUID or the Apple IOPlatformUUID.

Data Type: 128-bit universal unique identifier. For example:123e4567-e89b-12d3-a456-42661417400.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: The device manufacturer.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-DigitalCertificate"></a>

### DigitalCertificate
The Digital Certificate, also known as a Public Key Certificate, object
contains information about the ownership and usage of a public key. It serves
as a means to establish trust in the authenticity and integrity of the public
key and the associated entity.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| created_time | [int64](#int64) | optional | Description: The time when the certificate was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The time when the certificate was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| expiration_time | [int64](#int64) | optional | Description: The expiration time of the certificate.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| expiration_time_dt | [string](#string) | optional | Description: The expiration time of the certificate.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| fingerprints | [Fingerprint](#ocsf-v1alpha-Fingerprint) | repeated | Description: The fingerprint list of the certificate.

Data Type: A message field of type Fingerprint.

Requirement: recommended |
| is_self_signed | [bool](#bool) | optional | Description: Denotes whether a digital certificate is self-signed or signed by a known certificate authority (CA).

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| issuer | [string](#string) |  | Description: The certificate issuer distinguished name.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| sans | [SubjectAlternativeName](#ocsf-v1alpha-SubjectAlternativeName) | repeated | Description: The list of subject alternative names that are secured by a specific certificate.

Data Type: A message field of type SubjectAlternativeName.

Requirement: optional |
| serial_number | [string](#string) |  | Description: The serial number of the certificate used to create the digital signature.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| subject | [string](#string) | optional | Description: The certificate subject distinguished name.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The unique identifier of the certificate.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: The certificate version.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-DigitalSignature"></a>

### DigitalSignature
The Digital Signature object contains information about the cryptographic
mechanism used to verify the authenticity, integrity, and origin of the file
or application.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| algorithm | [string](#string) | optional | Description: The digital signature algorithm used to create the signature, normalized to the caption of &#39;algorithm_id&#39;. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| algorithm_id | [DigitalSignatureAlgorithmID](#ocsf-v1alpha-DigitalSignatureAlgorithmID) |  | Description: The identifier of the normalized digital signature algorithm.

Data Type: An enum field of type DigitalSignatureAlgorithmID.

Requirement: required |
| certificate | [DigitalCertificate](#ocsf-v1alpha-DigitalCertificate) | optional | Description: The certificate object containing information about the digital certificate.

Data Type: A message field of type DigitalCertificate.

Requirement: recommended |
| created_time | [int64](#int64) | optional | Description: The time when the digital signature was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: The time when the digital signature was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| developer_uid | [string](#string) | optional | Description: The developer ID on the certificate that signed the file.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| digest | [Fingerprint](#ocsf-v1alpha-Fingerprint) | optional | Description: The message digest attribute contains the fixed length message hash representation and the corresponding hashing algorithm information.

Data Type: A message field of type Fingerprint.

Requirement: optional |
| state | [string](#string) | optional | Description: The digital signature state defines the signature state, normalized to the caption of &#39;state_id&#39;. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| state_id | [DigitalSignatureStateID](#ocsf-v1alpha-DigitalSignatureStateID) | optional | Description: The normalized identifier of the signature state.

Data Type: An enum field of type DigitalSignatureStateID.

Requirement: optional |






<a name="ocsf-v1alpha-Display"></a>

### Display
The Display object contains information about the physical or virtual display
connected to a computer system.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| color_depth | [int32](#int32) | optional | Description: The numeric color depth.

Data Type: Signed integer value.

Requirement: optional |
| physical_height | [int32](#int32) | optional | Description: The numeric physical height of display.

Data Type: Signed integer value.

Requirement: optional |
| physical_orientation | [int32](#int32) | optional | Description: The numeric physical orientation of display.

Data Type: Signed integer value.

Requirement: optional |
| physical_width | [int32](#int32) | optional | Description: The numeric physical width of display.

Data Type: Signed integer value.

Requirement: optional |
| scale_factor | [int32](#int32) | optional | Description: The numeric scale factor of display.

Data Type: Signed integer value.

Requirement: optional |






<a name="ocsf-v1alpha-EPSS"></a>

### EPSS
The Exploit Prediction Scoring System (EPSS) object describes the estimated
probability a vulnerability will be exploited. EPSS is a community-driven
effort to combine descriptive information about vulnerabilities (CVEs) with
evidence of actual exploitation in-the-wild. (EPSS).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| created_time | [int64](#int64) | optional | Description: The timestamp indicating when the EPSS score was calculated.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The timestamp indicating when the EPSS score was calculated.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| percentile | [float](#float) | optional | Description: The EPSS score&#39;s percentile representing relative importance and ranking of the score in the larger EPSS dataset.

Data Type: Real floating-point value. For example:3.14.

Requirement: optional |
| score | [string](#string) |  | Description: The EPSS score representing the probability [0-1] of exploitation in the wild in the next 30 days (following score publication).

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| version | [string](#string) | optional | Description: The version of the EPSS model used to calculate the score.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-EncryptionDetails"></a>

### EncryptionDetails
Details about the encrytpion methodology utilized.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| algorithm | [string](#string) | optional | Description: The encryption algorithm used, normalized to the caption of &#39;algorithm_id

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| algorithm_id | [EncryptionDetailsAlgorithmID](#ocsf-v1alpha-EncryptionDetailsAlgorithmID) | optional | Description: The encryption algorithm used.

Data Type: An enum field of type EncryptionDetailsAlgorithmID.

Requirement: recommended |
| key_length | [int32](#int32) | optional | Description: The length of the encryption key used.

Data Type: Signed integer value.

Requirement: optional |
| key_uid | [string](#string) | optional | Description: The unique identifier of the key used for encrpytion. For example, AWS KMS Key ARN.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type | [string](#string) | optional | Description: The type of the encryption used.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-Enrichment"></a>

### Enrichment
The Enrichment object provides inline enrichment data for specific attributes
of interest within an event. It serves as a mechanism to enhance or
supplement the information associated with the event by adding additional
relevant details or context.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| created_time | [int64](#int64) | optional | Description: The time when the enrichment data was generated.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The time when the enrichment data was generated.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| data | [string](#string) |  | Description: The enrichment data associated with the attribute and value. The meaning of this data depends on the type the enrichment record.

Data Type: Embedded JSON value. A value can be a string, or a number, or true or false or null, or an object or an array. These structures can be nested. See www.json.org.

Requirement: required |
| desc | [string](#string) | optional | Description: A long description of the enrichment data.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) |  | Description: The name of the attribute to which the enriched data pertains.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| provider | [string](#string) | optional | Description: The enrichment data provider name.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| reputation | [Reputation](#ocsf-v1alpha-Reputation) | optional | Description: The reputation of the enrichment data.

Data Type: A message field of type Reputation.

Requirement: optional |
| short_desc | [string](#string) | optional | Description: A short description of the enrichment data.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| src_url | [string](#string) | optional | Description: The URL of the source of the enrichment data.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: recommended |
| type | [string](#string) | optional | Description: The enrichment type. For example: location.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| value | [string](#string) |  | Description: The value of the attribute to which the enriched data pertains.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-EnvironmentVariable"></a>

### EnvironmentVariable
An environment variable.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Description: The name of the environment variable.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| value | [string](#string) |  | Description: The value of the environment variable.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-Feature"></a>

### Feature
The Feature object provides information about the software product feature
that generated a specific event. It encompasses details related to the
capabilities, components, user interface (UI) design, and performance
upgrades associated with the feature.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The name of the feature.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the feature.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: The version of the feature.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-File"></a>

### File
The File object represents the metadata associated with a file stored in a
computer system. It encompasses information about the file itself, including
its attributes, properties, and organizational details.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| accessed_time | [int64](#int64) | optional | Description: The time when the file was last accessed.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| accessed_time_dt | [string](#string) | optional | Description: The time when the file was last accessed.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| accessor | [User](#ocsf-v1alpha-User) | optional | Description: The name of the user who last accessed the object.

Data Type: A message field of type User.

Requirement: optional |
| attributes | [int32](#int32) | optional | Description: The bitmask value that represents the file attributes.

Data Type: Signed integer value.

Requirement: optional |
| company_name | [string](#string) | optional | Description: The name of the company that published the file. For example: Microsoft Corporation.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| confidentiality | [string](#string) | optional | Description: The file content confidentiality, normalized to the confidentiality_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| confidentiality_id | [FileConfidentialityID](#ocsf-v1alpha-FileConfidentialityID) | optional | Description: The normalized identifier of the file content confidentiality indicator.

Data Type: An enum field of type FileConfidentialityID.

Requirement: optional |
| created_time | [int64](#int64) | optional | Description: The time when the file was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: The time when the file was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| creator | [User](#ocsf-v1alpha-User) | optional | Description: The user that created the file.

Data Type: A message field of type User.

Requirement: optional |
| desc | [string](#string) | optional | Description: The description of the file, as returned by file system. For example: the description as returned by the Unix file command or the Windows file type.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| drive_type | [string](#string) | optional | Description: The drive type, normalized to the caption of the drive_type_id value. In the case of Other, it is defined by the source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| drive_type_id | [FileDriveTypeID](#ocsf-v1alpha-FileDriveTypeID) | optional | Description: Identifies the type of a disk drive, i.e. fixed, removable, etc.

Data Type: An enum field of type FileDriveTypeID.

Requirement: optional |
| encryption_details | [EncryptionDetails](#ocsf-v1alpha-EncryptionDetails) | optional | Description: The encryption details of the file. Should be populated if the file is encrypted.

Data Type: A message field of type EncryptionDetails.

Requirement: optional |
| ext | [string](#string) | optional | Description: The extension of the file, excluding the leading dot. For example: exe from svchost.exe, or gz from export.tar.gz.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| hashes | [Fingerprint](#ocsf-v1alpha-Fingerprint) | repeated | Description: An array of hash attributes.

Data Type: A message field of type Fingerprint.

Requirement: recommended |
| internal_name | [string](#string) | optional | Description: The name of the file as identified within the file itself. This contrasts with the name by which the file is known on disk. Where available, the internal name is widely used by security practitioners and detection content because the on-disk file name is not reliable. On the Windows OS, most PE files contain a VERSIONINFO resource from which the internal name can be obtained. On macOS, binaries can optionally embed a copy of the application&#39;s Info.plist file which in turn contains the name of the executable.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| is_deleted | [bool](#bool) | optional | Description: Indicates if the file was deleted from the filesystem.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_encrypted | [bool](#bool) | optional | Description: Indicates if the file is encrypted.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_public | [bool](#bool) | optional | Description: Indicates if the file is publicly accessible. For example in an object&#39;s public access in AWS S3

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_system | [bool](#bool) | optional | Description: The indication of whether the object is part of the operating system.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| mime_type | [string](#string) | optional | Description: The Multipurpose Internet Mail Extensions (MIME) type of the file, if applicable.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The time when the file was last modified.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The time when the file was last modified.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| modifier | [User](#ocsf-v1alpha-User) | optional | Description: The user that last modified the file.

Data Type: A message field of type User.

Requirement: optional |
| name | [string](#string) |  | Description: The name of the file. For example: svchost.exe

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| owner | [User](#ocsf-v1alpha-User) | optional | Description: The user that owns the file/object.

Data Type: A message field of type User.

Requirement: optional |
| parent_folder | [string](#string) | optional | Description: The parent folder in which the file resides. For example: c:\windows\system32

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| path | [string](#string) | optional | Description: The full path to the file. For example: c:\windows\system32\svchost.exe.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| product | [Product](#ocsf-v1alpha-Product) | optional | Description: The product that created or installed the file.

Data Type: A message field of type Product.

Requirement: optional |
| security_descriptor | [string](#string) | optional | Description: The object security descriptor.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| signature | [DigitalSignature](#ocsf-v1alpha-DigitalSignature) | optional | Description: The digital signature of the file.

Data Type: A message field of type DigitalSignature.

Requirement: optional |
| size | [int64](#int64) | optional | Description: The size of data, in bytes.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| storage_class | [string](#string) | optional | Description: The storage class of the file. For example in AWS S3: STANDARD, STANDARD_IA, GLACIER.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| tags | [KeyValueobject](#ocsf-v1alpha-KeyValueobject) | repeated | Description: The list of tags; {key:value} pairs associated to the file.

Data Type: A message field of type KeyValueobject.

Requirement: optional |
| type | [string](#string) | optional | Description: The file type.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [FileTypeID](#ocsf-v1alpha-FileTypeID) |  | Description: The file type ID.

Data Type: An enum field of type FileTypeID.

Requirement: required |
| uid | [string](#string) | optional | Description: The unique identifier of the file as defined by the storage system, such the file system file ID.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| url | [UniformResourceLocator](#ocsf-v1alpha-UniformResourceLocator) | optional | Description: The URL of the file, when applicable.

Data Type: A message field of type UniformResourceLocator.

Requirement: optional |
| version | [string](#string) | optional | Description: The file version. For example: 8.0.7601.17514.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| xattributes | [Object](#ocsf-v1alpha-Object) | optional | Description: An unordered collection of zero or more name/value pairs where each pair represents a file or folder extended attribute.For example: Windows alternate data stream attributes (ADS stream name, ADS size, etc.), user- defined or application-defined attributes, ACL, owner, primary group, etc. Examples from DCS: ads_nameads_sizedaclownerprimary_grouplink_name - name of the link associated to the file.hard_link_count - the number of links that are associated to the file.

Data Type: A message field of type Object.

Requirement: optional |






<a name="ocsf-v1alpha-Fingerprint"></a>

### Fingerprint
The Fingerprint object provides detailed information about a digital
fingerprint, which is a compact representation of data used to identify a
longer piece of information, such as a public key or file content. It
contains the algorithm and value of the fingerprint, enabling efficient and
reliable identification of the associated data.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| algorithm | [string](#string) | optional | Description: The hash algorithm used to create the digital fingerprint, normalized to the caption of algorithm_id. In the case of Other, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| algorithm_id | [FingerprintAlgorithmID](#ocsf-v1alpha-FingerprintAlgorithmID) |  | Description: The identifier of the normalized hash algorithm, which was used to create the digital fingerprint.

Data Type: An enum field of type FingerprintAlgorithmID.

Requirement: required |
| value | [string](#string) |  | Description: The digital fingerprint value.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-FirewallRule"></a>

### FirewallRule
The Firewall Rule object represents a specific rule within a firewall policy
or event. It contains information about a rule&#39;s configuration, properties,
and associated actions that define how network traffic is handled by the
firewall.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| category | [string](#string) | optional | Description: The rule category.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| condition | [string](#string) | optional | Description: The rule trigger condition for the rule. For example: SQL_INJECTION.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| desc | [string](#string) | optional | Description: The description of the rule that generated the event.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| duration | [int64](#int64) | optional | Description: The rule response time duration, usually used for challenge completion time.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| match_details | [string](#string) | repeated | Description: The data in a request that rule matched. For example: &#39;[&#34;10&#34;,&#34;and&#34;,&#34;1&#34;]&#39;.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| match_location | [string](#string) | optional | Description: The location of the matched data in the source which resulted in the triggered firewall rule. For example: HEADER.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the rule that generated the event.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| rate_limit | [int32](#int32) | optional | Description: The rate limit for a rate-based rule.

Data Type: Signed integer value.

Requirement: optional |
| sensitivity | [string](#string) | optional | Description: The sensitivity of the firewall rule in the matched event. For example: HIGH.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type | [string](#string) | optional | Description: The rule type.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the rule that generated the event.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: The rule version. For example: 1.1.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-GeoLocation"></a>

### GeoLocation
The Geo Location object describes a geographical location, usually associated
with an IP address.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| aerial_height | [string](#string) | optional | Description: Expressed as either height above takeoff location or height above ground level (AGL) for a UAS current location. This value is provided in meters and must have a minimum resolution of 1 m. Special Values: Invalid, No Value, or Unknown: -1000 m.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| city | [string](#string) | optional | Description: The name of the city.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| continent | [string](#string) | optional | Description: The name of the continent.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| coordinates | [float](#float) | repeated | Description: A two-element array, containing a longitude/latitude pair. The format conforms with GeoJSON. For example: [-73.983, 40.719].

Data Type: Real floating-point value. For example:3.14.

Requirement: optional |
| country | [string](#string) | optional | Description: The ISO 3166-1 Alpha-2 country code.Note: The two letter country code should be capitalized. For example: US or CA.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| desc | [string](#string) | optional | Description: The description of the geographical location.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| geodetic_altitude | [string](#string) | optional | Description: The aircraft distance above or below the ellipsoid as measured along a line that passes through the aircraft and is normal to the surface of the WGS-84 ellipsoid. This value is provided in meters and must have a minimum resolution of 1 m. Special Values: Invalid, No Value, or Unknown: -1000 m.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| geodetic_vertical_accuracy | [string](#string) | optional | Description: Provides quality/containment on geodetic altitude. This is based on ADS-B Geodetic Vertical Accuracy (GVA). Measured in meters.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| geohash | [string](#string) | optional | Description: Geohash of the geo-coordinates (latitude and longitude).Geohashing is a geocoding system used to encode geographic coordinates in decimal degrees, to a single string.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| horizontal_accuracy | [string](#string) | optional | Description: Provides quality/containment on horizontal position. This is based on ADS-B NACp. Measured in meters.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| is_on_premises | [bool](#bool) | optional | Description: The indication of whether the location is on premises.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| isp | [string](#string) | optional | Description: The name of the Internet Service Provider (ISP).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| lat | [float](#float) | optional | Description: The geographical Latitude coordinate represented in Decimal Degrees (DD). For example: 42.361145.

Data Type: Real floating-point value. For example:3.14.

Requirement: optional |
| long | [float](#float) | optional | Description: The geographical Longitude coordinate represented in Decimal Degrees (DD). For example: -71.057083.

Data Type: Real floating-point value. For example:3.14.

Requirement: optional |
| postal_code | [string](#string) | optional | Description: The postal code of the location.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| pressure_altitude | [string](#string) | optional | Description: The uncorrected barometric pressure altitude (based on reference standard 29.92 inHg, 1013.25 mb) provides a reference for algorithms that utilize &#39;altitude deltas&#39; between aircraft. This value is provided in meters and must have a minimum resolution of 1 m.. Special Values: Invalid, No Value, or Unknown: -1000 m.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| provider | [string](#string) | optional | Description: The provider of the geographical location data.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| region | [string](#string) | optional | Description: The alphanumeric code that identifies the principal subdivision (e.g. province or state) of the country. For example, &#39;CH-VD&#39; for the Canton of Vaud, Switzerland

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Group"></a>

### Group
The Group object represents a collection or association of entities, such as
users, policies, or devices. It serves as a logical grouping mechanism to
organize and manage entities with similar characteristics or permissions
within a system or organization, including but not limited to purposes of
access control.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| desc | [string](#string) | optional | Description: The group description.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| domain | [string](#string) | optional | Description: The domain where the group is defined. For example: the LDAP or Active Directory domain.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The group name.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| privileges | [string](#string) | repeated | Description: The group privileges.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type | [string](#string) | optional | Description: The type of the group or account.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the group. For example, for Windows events this is the security identifier (SID) of the group.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-IdentityProvider"></a>

### IdentityProvider
The Identity Provider object contains detailed information about a provider
responsible for creating, maintaining, and managing identity information
while offering authentication services to applications. An Identity Provider
(IdP) serves as a trusted authority that verifies the identity of users and
issues authentication tokens or assertions to enable secure access to
applications or services.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| auth_factors | [AuthenticationFactor](#ocsf-v1alpha-AuthenticationFactor) | repeated | Description: The Authentication Factors object describes the different types of Multi- Factor Authentication (MFA) methods and/or devices supported by the Identity Provider.

Data Type: A message field of type AuthenticationFactor.

Requirement: optional |
| domain | [string](#string) | optional | Description: The primary domain associated with the Identity Provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| fingerprint | [Fingerprint](#ocsf-v1alpha-Fingerprint) | optional | Description: The fingerprint of the X.509 certificate used by the Identity Provider.

Data Type: A message field of type Fingerprint.

Requirement: optional |
| has_mfa | [bool](#bool) | optional | Description: The Identity Provider enforces Multi Factor Authentication (MFA).

Data Type: Boolean value. One of true or false.

Requirement: optional |
| issuer | [string](#string) | optional | Description: The unique identifier (often a URL) used by the Identity Provider as its issuer.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the Identity Provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| protocol_name | [string](#string) | optional | Description: The supported protocol of the Identity Provider. E.g., SAML, OIDC, or OAuth2.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| scim | [SCIM](#ocsf-v1alpha-SCIM) | optional | Description: The System for Cross-domain Identity Management (SCIM) resource object provides a structured set of attributes related to SCIM protocols used for identity provisioning and management across cloud-based platforms. It standardizes user and group provisioning details, enabling identity synchronization and lifecycle management with compatible Identity Providers (IdPs) and applications. SCIM is defined in RFC-7634

Data Type: A message field of type SCIM.

Requirement: optional |
| sso | [SSO](#ocsf-v1alpha-SSO) | optional | Description: The Single Sign-On (SSO) object provides a structure for normalizing SSO attributes, configuration, and/or settings from Identity Providers.

Data Type: A message field of type SSO.

Requirement: optional |
| state | [string](#string) | optional | Description: The configuration state of the Identity Provider, normalized to the caption of the state_id value. In the case of Other, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| state_id | [IdentityProviderStateID](#ocsf-v1alpha-IdentityProviderStateID) | optional | Description: The normalized state ID of the Identity Provider to reflect its configuration or activation status.

Data Type: An enum field of type IdentityProviderStateID.

Requirement: optional |
| tenant_uid | [string](#string) | optional | Description: The tenant ID associated with the Identity Provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the Identity Provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| url_string | [string](#string) | optional | Description: The URL for accessing the configuration or metadata of the Identity Provider.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |






<a name="ocsf-v1alpha-Image"></a>

### Image
The Image object provides a description of a specific Virtual Machine (VM) or
Container image.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| labels | [string](#string) | repeated | Description: The list of labels associated to the image.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The image name. For example: elixir.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| path | [string](#string) | optional | Description: The full path to the image file.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| tag | [string](#string) | optional | Description: The image tag. For example: 1.11-alpine.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| tags | [KeyValueobject](#ocsf-v1alpha-KeyValueobject) | repeated | Description: The list of tags; {key:value} pairs associated to the image.

Data Type: A message field of type KeyValueobject.

Requirement: optional |
| uid | [string](#string) |  | Description: The unique image ID. For example: 77af4d6b9913.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-JA4Fingerprint"></a>

### JA4Fingerprint
The JA4&#43; fingerprint object provides detailed fingerprint information about
various aspects of network traffic which is both machine and human readable.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| section_a | [string](#string) | optional | Description: The &#39;a&#39; section of the JA4 fingerprint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| section_b | [string](#string) | optional | Description: The &#39;b&#39; section of the JA4 fingerprint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| section_c | [string](#string) | optional | Description: The &#39;c&#39; section of the JA4 fingerprint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| section_d | [string](#string) | optional | Description: The &#39;d&#39; section of the JA4 fingerprint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type | [string](#string) | optional | Description: The JA4&#43; fingerprint type as defined by FoxIO, normalized to the caption of &#39;type_id&#39;. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [JA4FingerprintTypeID](#ocsf-v1alpha-JA4FingerprintTypeID) |  | Description: The identifier of the JA4&#43; fingerprint type.

Data Type: An enum field of type JA4FingerprintTypeID.

Requirement: required |
| value | [string](#string) |  | Description: The JA4&#43; fingerprint value.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-KeyValueobject"></a>

### KeyValueobject
A generic object allowing to define a {key:value} pair.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Description: The name of the key.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| value | [string](#string) | optional | Description: The value associated to the key.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| values | [string](#string) | repeated | Description: Optional, the values associated to the key. You can populate this attribute, when you have multiple values for the same key.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-KeyboardInformation"></a>

### KeyboardInformation
The Keyboard Information object contains details and attributes related to a
computer or device keyboard. It encompasses information that describes the
characteristics, capabilities, and configuration of the keyboard.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| function_keys | [int32](#int32) | optional | Description: The number of function keys on client keyboard.

Data Type: Signed integer value.

Requirement: optional |
| ime | [string](#string) | optional | Description: The Input Method Editor (IME) file name.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| keyboard_layout | [string](#string) | optional | Description: The keyboard locale identifier name (e.g., en-US).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| keyboard_subtype | [int32](#int32) | optional | Description: The keyboard numeric code.

Data Type: Signed integer value.

Requirement: optional |
| keyboard_type | [string](#string) | optional | Description: The keyboard type (e.g., xt, ico).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-LDAPPerson"></a>

### LDAPPerson
The additional LDAP attributes that describe a person.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cost_center | [string](#string) | optional | Description: The cost center associated with the user.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| created_time | [int64](#int64) | optional | Description: The timestamp when the user was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: The timestamp when the user was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| deleted_time | [int64](#int64) | optional | Description: The timestamp when the user was deleted. In Active Directory (AD), when a user is deleted they are moved to a temporary container and then removed after 30 days. So, this field can be populated even after a user is deleted for the next 30 days.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| deleted_time_dt | [string](#string) | optional | Description: The timestamp when the user was deleted. In Active Directory (AD), when a user is deleted they are moved to a temporary container and then removed after 30 days. So, this field can be populated even after a user is deleted for the next 30 days.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| email_addrs | [string](#string) | repeated | Description: A list of additional email addresses for the user.

Data Type: Email address. For example:john_doe@example.com.

Requirement: optional |
| employee_uid | [string](#string) | optional | Description: The employee identifier assigned to the user by the organization.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| given_name | [string](#string) | optional | Description: The given or first name of the user.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| hire_time | [int64](#int64) | optional | Description: The timestamp when the user was or will be hired by the organization.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| hire_time_dt | [string](#string) | optional | Description: The timestamp when the user was or will be hired by the organization.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| job_title | [string](#string) | optional | Description: The user&#39;s job title.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| labels | [string](#string) | repeated | Description: The labels associated with the user. For example in AD this could be the userType, employeeType. For example: Member, Employee.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| last_login_time | [int64](#int64) | optional | Description: The last time when the user logged in.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| last_login_time_dt | [string](#string) | optional | Description: The last time when the user logged in.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| ldap_cn | [string](#string) | optional | Description: The LDAP and X.500 commonName attribute, typically the full name of the person. For example, John Doe.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| ldap_dn | [string](#string) | optional | Description: The X.500 Distinguished Name (DN) is a structured string that uniquely identifies an entry, such as a user, in an X.500 directory service For example, cn=John Doe,ou=People,dc=example,dc=com.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| leave_time | [int64](#int64) | optional | Description: The timestamp when the user left or will be leaving the organization.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| leave_time_dt | [string](#string) | optional | Description: The timestamp when the user left or will be leaving the organization.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| location | [GeoLocation](#ocsf-v1alpha-GeoLocation) | optional | Description: The geographical location associated with a user. This is typically the user&#39;s usual work location.

Data Type: A message field of type GeoLocation.

Requirement: optional |
| manager | [User](#ocsf-v1alpha-User) | optional | Description: The user&#39;s manager. This helps in understanding an org hierarchy. This should only ever be populated once in an event. I.e. there should not be a manager&#39;s manager in an event.

Data Type: A message field of type User.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The timestamp when the user entry was last modified.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The timestamp when the user entry was last modified.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| office_location | [string](#string) | optional | Description: The primary office location associated with the user. This could be any string and isn&#39;t a specific address. For example, South East Virtual.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| phone_number | [string](#string) | optional | Description: The telephone number of the user. Corresponds to the LDAP Telephone- Number CN.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| surname | [string](#string) | optional | Description: The last or family name for the user.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| tags | [KeyValueobject](#ocsf-v1alpha-KeyValueobject) | repeated | Description: The list of tags; {key:value} pairs associated to the user.

Data Type: A message field of type KeyValueobject.

Requirement: optional |






<a name="ocsf-v1alpha-Logger"></a>

### Logger
The Logger object represents the device and product where events are stored
with times for receipt and transmission.  This may be at the source device
where the event occurred, a remote scanning device, intermediate hops, or the
ultimate destination.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| device | [Device](#ocsf-v1alpha-Device) | optional | Description: The device where the events are logged.

Data Type: A message field of type Device.

Requirement: recommended |
| event_uid | [string](#string) | optional | Description: The unique identifier of the event assigned by the logger.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| log_level | [string](#string) | optional | Description: The audit level at which an event was generated.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| log_name | [string](#string) | optional | Description: The event log name. For example, syslog file name or Windows logging subsystem: Security.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| log_provider | [string](#string) | optional | Description: The logging provider or logging service that logged the event. For example, Microsoft-Windows-Security-Auditing.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| log_version | [string](#string) | optional | Description: The event log schema version that specifies the format of the original event. For example syslog version or Cisco Log Schema Version.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| logged_time | [int64](#int64) | optional | Description: The time when the logging system collected and logged the event.This attribute is distinct from the event time in that event time typically contain the time extracted from the original event. Most of the time, these two times will be different.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| logged_time_dt | [string](#string) | optional | Description: The time when the logging system collected and logged the event.This attribute is distinct from the event time in that event time typically contain the time extracted from the original event. Most of the time, these two times will be different.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the logging product instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| product | [Product](#ocsf-v1alpha-Product) | optional | Description: The product logging the event. This may be the event source product, a management server product, a scanning product, a SIEM, etc.

Data Type: A message field of type Product.

Requirement: recommended |
| transmit_time | [int64](#int64) | optional | Description: The time when the event was transmitted from the logging device to it&#39;s next destination.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| transmit_time_dt | [string](#string) | optional | Description: The time when the event was transmitted from the logging device to it&#39;s next destination.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the logging product instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| version | [string](#string) | optional | Description: The version of the logging product.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-MITREATTCK"></a>

### MITREATTCK
The MITRE ATT&amp;CK® object describes the tactic, technique &amp; sub-technique
associated to an attack as defined in ATT&amp;CK® Matrix.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| sub_technique | [MITREATTCKSubTechnique](#ocsf-v1alpha-MITREATTCKSubTechnique) | optional | Description: The Sub Technique object describes the sub technique ID and/or name associated to an attack, as defined by ATT&amp;CK® Matrix.

Data Type: A message field of type MITREATTCKSubTechnique.

Requirement: optional |
| tactic | [MITREATTCKTactic](#ocsf-v1alpha-MITREATTCKTactic) | optional | Description: The Tactic object describes the tactic ID and/or name that is associated to an attack, as defined by ATT&amp;CK® Matrix.

Data Type: A message field of type MITREATTCKTactic.

Requirement: optional |
| tactics | [MITREATTCKTactic](#ocsf-v1alpha-MITREATTCKTactic) | repeated | Description: The Tactic object describes the tactic ID and/or tactic name that are associated with the attack technique, as defined by ATT&amp;CK® Matrix.

Data Type: A message field of type MITREATTCKTactic.

Requirement: optional |
| technique | [MITREATTCKTechnique](#ocsf-v1alpha-MITREATTCKTechnique) | optional | Description: The Technique object describes the technique ID and/or name associated to an attack, as defined by ATT&amp;CK® Matrix.

Data Type: A message field of type MITREATTCKTechnique.

Requirement: optional |
| version | [string](#string) | optional | Description: The ATT&amp;CK® Matrix version.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-MITREATTCKSubTechnique"></a>

### MITREATTCKSubTechnique
The MITRE ATT&amp;CK® Sub Technique object describes the sub technique ID and/or
name associated to an attack, as defined by ATT&amp;CK® Matrix.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The name of the attack sub technique, as defined by ATT&amp;CK® Matrix. For example: Scanning IP Blocks.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| src_url | [string](#string) | optional | Description: The versioned permalink of the attack sub technique, as defined by ATT&amp;CK® Matrix. For example: https://attack.mitre.org/versions/v14/techniques/T1595/001/.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the attack sub technique, as defined by ATT&amp;CK® Matrix. For example: T1595.001.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-MITREATTCKTactic"></a>

### MITREATTCKTactic
The MITRE ATT&amp;CK® Tactic object describes the tactic ID and/or name that is
associated to an attack, as defined by ATT&amp;CK® Matrix.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The tactic name that is associated with the attack technique, as defined by ATT&amp;CK® Matrix. For example: Reconnaissance.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| src_url | [string](#string) | optional | Description: The versioned permalink of the attack tactic, as defined by ATT&amp;CK® Matrix. For example: https://attack.mitre.org/versions/v14/tactics/TA0043/.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| uid | [string](#string) | optional | Description: The tactic ID that is associated with the attack technique, as defined by ATT&amp;CK® Matrix. For example: TA0043.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-MITREATTCKTechnique"></a>

### MITREATTCKTechnique
The MITRE ATT&amp;CK® Technique object describes the technique ID and/or name
associated to an attack, as defined by ATT&amp;CK® Matrix.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The name of the attack technique, as defined by ATT&amp;CK® Matrix. For example: Active Scanning.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| src_url | [string](#string) | optional | Description: The versioned permalink of the attack technique, as defined by ATT&amp;CK® Matrix. For example: https://attack.mitre.org/versions/v14/techniques/T1595/.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the attack technique, as defined by ATT&amp;CK® Matrix. For example: T1595.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Malware"></a>

### Malware
The Malware object describes the classification of known malicious software,
which is intentionally designed to cause damage to a computer, server,
client, or computer network.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| classification_ids | [MalwareClassificationIDs](#ocsf-v1alpha-MalwareClassificationIDs) | repeated | Description: The list of normalized identifiers of the malware classifications. Reference: STIX Malware Types

Data Type: An enum field of type MalwareClassificationIDs.

Requirement: required |
| classifications | [string](#string) | repeated | Description: The list of malware classifications, normalized to the captions of the classification_ids values. In the case of &#39;Other&#39;, they are defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cves | [CVE](#ocsf-v1alpha-CVE) | repeated | Description: List of Common Vulnerabilities and Exposures (CVE).

Data Type: A message field of type CVE.

Requirement: optional |
| name | [string](#string) | optional | Description: The malware name, as reported by the detection engine.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| path | [string](#string) | optional | Description: The filesystem path of the malware that was observed.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| provider | [string](#string) | optional | Description: The provider of the malware information.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The malware unique identifier, as reported by the detection engine. For example a virus id or an IPS signature id.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Metadata"></a>

### Metadata
The Metadata object describes the metadata associated with the event.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| correlation_uid | [string](#string) | optional | Description: The unique identifier used to correlate events.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| debug | [string](#string) | repeated | Description: Debug information about non-fatal issues with this OCSF event. Each issue is a line in this string array.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| event_code | [string](#string) | optional | Description: The Event ID, Code, or Name that the product uses to primarily identify the event.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| extension | [SchemaExtension](#ocsf-v1alpha-SchemaExtension) | optional | Description: The schema extension used to create the event.

Data Type: A message field of type SchemaExtension.

Requirement: optional |
| extensions | [SchemaExtension](#ocsf-v1alpha-SchemaExtension) | repeated | Description: The schema extensions used to create the event.

Data Type: A message field of type SchemaExtension.

Requirement: optional |
| labels | [string](#string) | repeated | Description: The list of labels attached to the event. For example: [&#34;sample&#34;, &#34;dev&#34;]

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| log_level | [string](#string) | optional | Description: The audit level at which an event was generated.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| log_name | [string](#string) | optional | Description: The event log name. For example, syslog file name or Windows logging subsystem: Security.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| log_provider | [string](#string) | optional | Description: The logging provider or logging service that logged the event. For example, Microsoft-Windows-Security-Auditing.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| log_version | [string](#string) | optional | Description: The event log schema version that specifies the format of the original event. For example syslog version or Cisco Log Schema Version.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| logged_time | [int64](#int64) | optional | Description: The time when the logging system collected and logged the event.This attribute is distinct from the event time in that event time typically contain the time extracted from the original event. Most of the time, these two times will be different.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| logged_time_dt | [string](#string) | optional | Description: The time when the logging system collected and logged the event.This attribute is distinct from the event time in that event time typically contain the time extracted from the original event. Most of the time, these two times will be different.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| loggers | [Logger](#ocsf-v1alpha-Logger) | repeated | Description: An array of Logger objects that describe the devices and logging products between the event source and its eventual destination. Note, this attribute can be used when there is a complex end-to-end path of event flow.

Data Type: A message field of type Logger.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The time when the event was last modified or enriched.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The time when the event was last modified or enriched.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| original_time | [string](#string) | optional | Description: The original event time as reported by the event source. For example, the time in the original format from system event log such as Syslog on Unix/Linux and the System event file on Windows. Omit if event is generated instead of collected via logs.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| processed_time | [int64](#int64) | optional | Description: The event processed time, such as an ETL operation.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| processed_time_dt | [string](#string) | optional | Description: The event processed time, such as an ETL operation.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| product | [Product](#ocsf-v1alpha-Product) |  | Description: The product that reported the event.

Data Type: A message field of type Product.

Requirement: required |
| profiles | [string](#string) | repeated | Description: The list of profiles used to create the event. Profiles should be referenced by their name attribute for core profiles, or extension/name for profiles from extensions.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| sequence | [int32](#int32) | optional | Description: Sequence number of the event. The sequence number is a value available in some events, to make the exact ordering of events unambiguous, regardless of the event time precision.

Data Type: Signed integer value.

Requirement: optional |
| tags | [KeyValueobject](#ocsf-v1alpha-KeyValueobject) | repeated | Description: The list of tags; {key:value} pairs associated to the event.

Data Type: A message field of type KeyValueobject.

Requirement: optional |
| tenant_uid | [string](#string) | optional | Description: The unique tenant identifier.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The logging system-assigned unique identifier of an event instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) |  | Description: The version of the OCSF schema, using Semantic Versioning Specification (SemVer). For example: 1.0.0. Event consumers use the version to determine the available event attributes.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-Metric"></a>

### Metric
The Metric object defines a simple name/value pair entity for a metric.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Description: The name of the metric.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| value | [string](#string) |  | Description: The value of the metric.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-NetworkActivity"></a>

### NetworkActivity
Network Activity events report network connection and traffic activity.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| action | [string](#string) | optional | Description: The normalized caption of action_id.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| action_id | [SecurityControlActionID](#ocsf-v1alpha-SecurityControlActionID) | optional | Description: The action taken by a control or other policy-based system leading to an outcome or disposition. An unknown action may still correspond to a known disposition. Refer to disposition_id for the outcome of the action.

Data Type: An enum field of type SecurityControlActionID.

Requirement: recommended |
| activity_id | [NetworkActivityActivityID](#ocsf-v1alpha-NetworkActivityActivityID) | optional | Description: The normalized identifier of the activity that triggered the event.

Data Type: An enum field of type NetworkActivityActivityID.

Requirement: optional |
| activity_name | [string](#string) | optional | Description: The event activity name, as defined by the activity_id.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| actor | [Actor](#ocsf-v1alpha-Actor) | optional | Description: The actor object describes details about the user/role/process that was the source of the activity. Note that this is not the threat actor of a campaign but may be part of a campaign.

Data Type: A message field of type Actor.

Requirement: optional |
| app_name | [string](#string) | optional | Description: The name of the application associated with the event or object.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| attacks | [MITREATTCK](#ocsf-v1alpha-MITREATTCK) | repeated | Description: An array of MITRE ATT&amp;CK® objects describing identified tactics, techniques &amp; sub-techniques.

Data Type: A message field of type MITREATTCK.

Requirement: optional |
| authorizations | [AuthorizationResult](#ocsf-v1alpha-AuthorizationResult) | repeated | Description: Provides details about an authorization, such as authorization outcome, and any associated policies related to the activity/event.

Data Type: A message field of type AuthorizationResult.

Requirement: optional |
| category_name | [string](#string) | optional | Description: The event category name, as defined by category_uid value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| category_uid | [CategoryID](#ocsf-v1alpha-CategoryID) |  | Description: The category unique identifier of the event.

Data Type: An enum field of type CategoryID.

Requirement: required |
| class_name | [string](#string) | optional | Description: The event class name, as defined by class_uid value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| class_uid | [ClassID](#ocsf-v1alpha-ClassID) |  | Description: The unique identifier of a class. A class describes the attributes available in an event.

Data Type: An enum field of type ClassID.

Requirement: required |
| confidence | [string](#string) | optional | Description: The confidence, normalized to the caption of the confidence_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| confidence_id | [SecurityControlConfidenceID](#ocsf-v1alpha-SecurityControlConfidenceID) | optional | Description: The normalized confidence refers to the accuracy of the rule that created the finding. A rule with a low confidence means that the finding scope is wide and may create finding reports that may not be malicious in nature.

Data Type: An enum field of type SecurityControlConfidenceID.

Requirement: recommended |
| confidence_score | [int32](#int32) | optional | Description: The confidence score as reported by the event source.

Data Type: Signed integer value.

Requirement: optional |
| connection_info | [NetworkConnectionInformation](#ocsf-v1alpha-NetworkConnectionInformation) | optional | Description: The network connection information.

Data Type: A message field of type NetworkConnectionInformation.

Requirement: recommended |
| count | [int32](#int32) | optional | Description: The number of times that events in the same logical group occurred during the event Start Time to End Time period.

Data Type: Signed integer value.

Requirement: optional |
| device | [Device](#ocsf-v1alpha-Device) | optional | Description: An addressable device, computer system or host.

Data Type: A message field of type Device.

Requirement: recommended |
| disposition | [string](#string) | optional | Description: The disposition name, normalized to the caption of the disposition_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| disposition_id | [SecurityControlDispositionID](#ocsf-v1alpha-SecurityControlDispositionID) | optional | Description: Describes the outcome or action taken by a security control, such as access control checks, malware detections or various types of policy violations.

Data Type: An enum field of type SecurityControlDispositionID.

Requirement: recommended |
| dst_endpoint | [NetworkEndpoint](#ocsf-v1alpha-NetworkEndpoint) | optional | Description: The responder (server) in a network connection.

Data Type: A message field of type NetworkEndpoint.

Requirement: recommended |
| duration | [int64](#int64) | optional | Description: The event duration or aggregate time, the amount of time the event covers from start_time to end_time in milliseconds.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| end_time | [int64](#int64) | optional | Description: The end time of a time period, or the time of the most recent event included in the aggregate event.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| end_time_dt | [string](#string) | optional | Description: The end time of a time period, or the time of the most recent event included in the aggregate event.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| enrichments | [Enrichment](#ocsf-v1alpha-Enrichment) | repeated | Description: The additional information from an external data source, which is associated with the event or a finding. For example add location information for the IP address in the DNS answers:[{&#34;name&#34;: &#34;answers.ip&#34;, &#34;value&#34;: &#34;92.24.47.250&#34;, &#34;type&#34;: &#34;location&#34;, &#34;data&#34;: {&#34;city&#34;: &#34;Socotra&#34;, &#34;continent&#34;: &#34;Asia&#34;, &#34;coordinates&#34;: [-25.4153, 17.0743], &#34;country&#34;: &#34;YE&#34;, &#34;desc&#34;: &#34;Yemen&#34;}}]

Data Type: A message field of type Enrichment.

Requirement: optional |
| firewall_rule | [FirewallRule](#ocsf-v1alpha-FirewallRule) | optional | Description: The firewall rule that pertains to the control that triggered the event, if applicable.

Data Type: A message field of type FirewallRule.

Requirement: optional |
| is_alert | [bool](#bool) | optional | Description: Indicates that the event is considered to be an alertable signal. Should be set to true if disposition_id = Alert among other dispositions, and/or risk_level_id or severity_id of the event is elevated. Not all control events will be alertable, for example if disposition_id = Exonerated or disposition_id = Allowed.

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| ja4_fingerprint_list | [JA4Fingerprint](#ocsf-v1alpha-JA4Fingerprint) | repeated | Description: A list of the JA4&#43; network fingerprints.

Data Type: A message field of type JA4Fingerprint.

Requirement: optional |
| malware | [Malware](#ocsf-v1alpha-Malware) | repeated | Description: A list of Malware objects, describing details about the identified malware.

Data Type: A message field of type Malware.

Requirement: optional |
| message | [string](#string) | optional | Description: The description of the event/finding, as defined by the source.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| metadata | [Metadata](#ocsf-v1alpha-Metadata) |  | Description: The metadata associated with the event or a finding.

Data Type: A message field of type Metadata.

Requirement: required |
| observables | [Observable](#ocsf-v1alpha-Observable) | repeated | Description: The observables associated with the event or a finding.

Data Type: A message field of type Observable.

Requirement: recommended |
| policy | [Policy](#ocsf-v1alpha-Policy) | optional | Description: The policy that pertains to the control that triggered the event, if applicable. For example the name of an anti-malware policy or an access control policy.

Data Type: A message field of type Policy.

Requirement: optional |
| proxy | [NetworkProxyEndpoint](#ocsf-v1alpha-NetworkProxyEndpoint) | optional | Description: The proxy (server) in a network connection.

Data Type: A message field of type NetworkProxyEndpoint.

Requirement: recommended |
| raw_data | [string](#string) | optional | Description: The raw event/finding data as received from the source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_details | [string](#string) | optional | Description: Describes the risk associated with the finding.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_level | [string](#string) | optional | Description: The risk level, normalized to the caption of the risk_level_id value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_level_id | [SecurityControlRiskLevelID](#ocsf-v1alpha-SecurityControlRiskLevelID) | optional | Description: The normalized risk level id.

Data Type: An enum field of type SecurityControlRiskLevelID.

Requirement: optional |
| risk_score | [int32](#int32) | optional | Description: The risk score as reported by the event source.

Data Type: Signed integer value.

Requirement: optional |
| severity | [string](#string) | optional | Description: The event/finding severity, normalized to the caption of the severity_id value. In the case of &#39;Other&#39;, it is defined by the source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| severity_id | [BaseEventSeverityID](#ocsf-v1alpha-BaseEventSeverityID) |  | Description: The normalized identifier of the event/finding severity.The normalized severity is a measurement the effort and expense required to manage and resolve an event or incident. Smaller numerical values represent lower impact events, and larger numerical values represent higher impact events.

Data Type: An enum field of type BaseEventSeverityID.

Requirement: required |
| src_endpoint | [NetworkEndpoint](#ocsf-v1alpha-NetworkEndpoint) | optional | Description: The initiator (client) of the network connection.

Data Type: A message field of type NetworkEndpoint.

Requirement: recommended |
| start_time | [int64](#int64) | optional | Description: The start time of a time period, or the time of the least recent event included in the aggregate event.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| start_time_dt | [string](#string) | optional | Description: The start time of a time period, or the time of the least recent event included in the aggregate event.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| status | [string](#string) | optional | Description: The event status, normalized to the caption of the status_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| status_code | [string](#string) | optional | Description: The event status code, as reported by the event source.For example, in a Windows Failed Authentication event, this would be the value of &#39;Failure Code&#39;, e.g. 0x18.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| status_detail | [string](#string) | optional | Description: The status detail contains additional information about the event/finding outcome.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| status_id | [BaseEventStatusID](#ocsf-v1alpha-BaseEventStatusID) | optional | Description: The normalized identifier of the event status.

Data Type: An enum field of type BaseEventStatusID.

Requirement: recommended |
| time | [int64](#int64) |  | Description: The normalized event occurrence time or the finding creation time.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: required |
| time_dt | [string](#string) | optional | Description: The normalized event occurrence time or the finding creation time.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| timezone_offset | [int32](#int32) | optional | Description: The number of minutes that the reported event time is ahead or behind UTC, in the range -1,080 to &#43;1,080.

Data Type: Signed integer value.

Requirement: recommended |
| tls | [TransportLayerSecurityTLS](#ocsf-v1alpha-TransportLayerSecurityTLS) | optional | Description: The Transport Layer Security (TLS) attributes.

Data Type: A message field of type TransportLayerSecurityTLS.

Requirement: optional |
| traffic | [NetworkTraffic](#ocsf-v1alpha-NetworkTraffic) | optional | Description: The network traffic refers to the amount of data moving across a network at a given point of time. Intended to be used alongside Network Connection.

Data Type: A message field of type NetworkTraffic.

Requirement: recommended |
| type_name | [string](#string) | optional | Description: The event/finding type name, as defined by the type_uid.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_uid | [int64](#int64) |  | Description: The event/finding type ID. It identifies the event&#39;s semantics and structure. The value is calculated by the logging system as: class_uid * 100 &#43; activity_id.

Data Type: 8-byte long, signed integer value.

Requirement: required |
| unmapped | [Object](#ocsf-v1alpha-Object) | optional | Description: The attributes that are not mapped to the event schema. The names and values of those attributes are specific to the event source.

Data Type: A message field of type Object.

Requirement: optional |
| url | [UniformResourceLocator](#ocsf-v1alpha-UniformResourceLocator) | optional | Description: The URL details relevant to the network traffic.

Data Type: A message field of type UniformResourceLocator.

Requirement: recommended |






<a name="ocsf-v1alpha-NetworkConnectionInformation"></a>

### NetworkConnectionInformation
The Network Connection Information object describes characteristics of an OSI
Transport Layer communication, including TCP and UDP.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| boundary | [string](#string) | optional | Description: The boundary of the connection, normalized to the caption of &#39;boundary_id&#39;. In the case of &#39;Other&#39;, it is defined by the event source. For cloud connections, this translates to the traffic-boundary(same VPC, through IGW, etc.). For traditional networks, this is described as Local, Internal, or External.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| boundary_id | [NetworkConnectionInformationBoundaryID](#ocsf-v1alpha-NetworkConnectionInformationBoundaryID) | optional | Description: The normalized identifier of the boundary of the connection. For cloud connections, this translates to the traffic-boundary (same VPC, through IGW, etc.). For traditional networks, this is described as Local, Internal, or External.

Data Type: An enum field of type NetworkConnectionInformationBoundaryID.

Requirement: recommended |
| community_uid | [string](#string) | optional | Description: The Community ID of the network connection.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| direction | [string](#string) | optional | Description: The direction of the initiated connection, traffic, or email, normalized to the caption of the direction_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| direction_id | [NetworkConnectionInformationDirectionID](#ocsf-v1alpha-NetworkConnectionInformationDirectionID) |  | Description: The normalized identifier of the direction of the initiated connection, traffic, or email.

Data Type: An enum field of type NetworkConnectionInformationDirectionID.

Requirement: required |
| flag_history | [string](#string) | optional | Description: The Connection Flag History summarizes events in a network connection. For example flags ShAD representing SYN, SYN/ACK, ACK and Data exchange.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| protocol_name | [string](#string) | optional | Description: The IP protocol name in lowercase, as defined by the Internet Assigned Numbers Authority (IANA). For example: tcp or udp.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| protocol_num | [int32](#int32) | optional | Description: The IP protocol number, as defined by the Internet Assigned Numbers Authority (IANA). For example: 6 for TCP and 17 for UDP.

Data Type: Signed integer value.

Requirement: recommended |
| protocol_ver | [string](#string) | optional | Description: The Internet Protocol version.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| protocol_ver_id | [NetworkConnectionInformationProtocolVersionID](#ocsf-v1alpha-NetworkConnectionInformationProtocolVersionID) | optional | Description: The Internet Protocol version identifier.

Data Type: An enum field of type NetworkConnectionInformationProtocolVersionID.

Requirement: recommended |
| session | [Session](#ocsf-v1alpha-Session) | optional | Description: The authenticated user or service session.

Data Type: A message field of type Session.

Requirement: optional |
| tcp_flags | [int32](#int32) | optional | Description: The network connection TCP header flags (i.e., control bits).

Data Type: Signed integer value.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the connection.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-NetworkEndpoint"></a>

### NetworkEndpoint
The Network Endpoint object describes characteristics of a network endpoint.
These can be a source or destination of a network connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_list | [Agent](#ocsf-v1alpha-Agent) | repeated | Description: A list of agent objects associated with a device, endpoint, or resource.

Data Type: A message field of type Agent.

Requirement: optional |
| autonomous_system | [AutonomousSystem](#ocsf-v1alpha-AutonomousSystem) | optional | Description: The Autonomous System details associated with an IP address.

Data Type: A message field of type AutonomousSystem.

Requirement: optional |
| domain | [string](#string) | optional | Description: The name of the domain that the endpoint belongs to or that corresponds to the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| hostname | [string](#string) | optional | Description: The fully qualified name of the endpoint.

Data Type: Unique name assigned to a device connected to a computer network. It may be a fully qualified domain name (FQDN). For example:r2-d2.example.com.,mx.example.com

Requirement: recommended |
| hw_info | [DeviceHardwareInfo](#ocsf-v1alpha-DeviceHardwareInfo) | optional | Description: The endpoint hardware information.

Data Type: A message field of type DeviceHardwareInfo.

Requirement: optional |
| instance_uid | [string](#string) | optional | Description: The unique identifier of a VM instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_name | [string](#string) | optional | Description: The name of the network interface (e.g. eth2).

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_uid | [string](#string) | optional | Description: The unique identifier of the network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| intermediate_ips | [string](#string) | repeated | Description: The intermediate IP Addresses. For example, the IP addresses in the HTTP X-Forwarded-For header.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: optional |
| ip | [string](#string) | optional | Description: The IP address of the endpoint, in either IPv4 or IPv6 format.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: recommended |
| location | [GeoLocation](#ocsf-v1alpha-GeoLocation) | optional | Description: The geographical location of the endpoint.

Data Type: A message field of type GeoLocation.

Requirement: optional |
| mac | [string](#string) | optional | Description: The Media Access Control (MAC) address of the endpoint.

Data Type: Media Access Control (MAC) address. For example:18:36:F3:98:4F:9A.

Requirement: optional |
| name | [string](#string) | optional | Description: The short name of the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| os | [OperatingSystemOS](#ocsf-v1alpha-OperatingSystemOS) | optional | Description: The endpoint operating system.

Data Type: A message field of type OperatingSystemOS.

Requirement: optional |
| owner | [User](#ocsf-v1alpha-User) | optional | Description: The identity of the service or user account that owns the endpoint or was last logged into it.

Data Type: A message field of type User.

Requirement: recommended |
| port | [int32](#int32) | optional | Description: The port used for communication within the network connection.

Data Type: The TCP/UDP port number. For example:80,22.

Requirement: recommended |
| proxy_endpoint | [NetworkProxyEndpoint](#ocsf-v1alpha-NetworkProxyEndpoint) | optional | Description: The network proxy information pertaining to a specific endpoint. This can be used to describe information pertaining to network address translation (NAT).

Data Type: A message field of type NetworkProxyEndpoint.

Requirement: optional |
| subnet_uid | [string](#string) | optional | Description: The unique identifier of a virtual subnet.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| svc_name | [string](#string) | optional | Description: The service name in service-to-service connections. For example, AWS VPC logs the pkt-src-aws-service and pkt-dst-aws-service fields identify the connection is coming from or going to an AWS service.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| type | [string](#string) | optional | Description: The network endpoint type. For example: unknown, server, desktop, laptop, tablet, mobile, virtual, browser, or other.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [NetworkEndpointTypeID](#ocsf-v1alpha-NetworkEndpointTypeID) | optional | Description: The network endpoint type ID.

Data Type: An enum field of type NetworkEndpointTypeID.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vlan_uid | [string](#string) | optional | Description: The Virtual LAN identifier.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vpc_uid | [string](#string) | optional | Description: The unique identifier of the Virtual Private Cloud (VPC).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| zone | [string](#string) | optional | Description: The network zone or LAN segment.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-NetworkInterface"></a>

### NetworkInterface
The Network Interface object describes the type and associated attributes of
a network interface.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| hostname | [string](#string) | optional | Description: The hostname associated with the network interface.

Data Type: Unique name assigned to a device connected to a computer network. It may be a fully qualified domain name (FQDN). For example:r2-d2.example.com.,mx.example.com

Requirement: recommended |
| ip | [string](#string) | optional | Description: The IP address associated with the network interface.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: recommended |
| mac | [string](#string) | optional | Description: The MAC address of the network interface.

Data Type: Media Access Control (MAC) address. For example:18:36:F3:98:4F:9A.

Requirement: recommended |
| name | [string](#string) | optional | Description: The name of the network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| namespace | [string](#string) | optional | Description: The namespace is useful in merger or acquisition situations. For example, when similar entities exist that you need to keep separate.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| subnet_prefix | [int32](#int32) | optional | Description: The subnet prefix length determines the number of bits used to represent the network part of the IP address. The remaining bits are reserved for identifying individual hosts within that subnet.

Data Type: Signed integer value.

Requirement: optional |
| type | [string](#string) | optional | Description: The type of network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [NetworkInterfaceTypeID](#ocsf-v1alpha-NetworkInterfaceTypeID) |  | Description: The network interface type identifier.

Data Type: An enum field of type NetworkInterfaceTypeID.

Requirement: required |
| uid | [string](#string) | optional | Description: The unique identifier for the network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-NetworkProxyEndpoint"></a>

### NetworkProxyEndpoint
The network proxy endpoint object describes a proxy server, which acts as an
intermediary between a client requesting a resource and the server providing
that resource.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| agent_list | [Agent](#ocsf-v1alpha-Agent) | repeated | Description: A list of agent objects associated with a device, endpoint, or resource.

Data Type: A message field of type Agent.

Requirement: optional |
| autonomous_system | [AutonomousSystem](#ocsf-v1alpha-AutonomousSystem) | optional | Description: The Autonomous System details associated with an IP address.

Data Type: A message field of type AutonomousSystem.

Requirement: optional |
| domain | [string](#string) | optional | Description: The name of the domain that the endpoint belongs to or that corresponds to the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| hostname | [string](#string) | optional | Description: The fully qualified name of the endpoint.

Data Type: Unique name assigned to a device connected to a computer network. It may be a fully qualified domain name (FQDN). For example:r2-d2.example.com.,mx.example.com

Requirement: recommended |
| hw_info | [DeviceHardwareInfo](#ocsf-v1alpha-DeviceHardwareInfo) | optional | Description: The endpoint hardware information.

Data Type: A message field of type DeviceHardwareInfo.

Requirement: optional |
| instance_uid | [string](#string) | optional | Description: The unique identifier of a VM instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_name | [string](#string) | optional | Description: The name of the network interface (e.g. eth2).

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| interface_uid | [string](#string) | optional | Description: The unique identifier of the network interface.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| intermediate_ips | [string](#string) | repeated | Description: The intermediate IP Addresses. For example, the IP addresses in the HTTP X-Forwarded-For header.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: optional |
| ip | [string](#string) | optional | Description: The IP address of the endpoint, in either IPv4 or IPv6 format.

Data Type: Internet Protocol address (IP address), in either IPv4 or IPv6 format. For example:192.168.200.24, 2001:0db8:85a3:0000:0000:8a2e:0370:7334.

Requirement: recommended |
| location | [GeoLocation](#ocsf-v1alpha-GeoLocation) | optional | Description: The geographical location of the endpoint.

Data Type: A message field of type GeoLocation.

Requirement: optional |
| mac | [string](#string) | optional | Description: The Media Access Control (MAC) address of the endpoint.

Data Type: Media Access Control (MAC) address. For example:18:36:F3:98:4F:9A.

Requirement: optional |
| name | [string](#string) | optional | Description: The short name of the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| os | [OperatingSystemOS](#ocsf-v1alpha-OperatingSystemOS) | optional | Description: The endpoint operating system.

Data Type: A message field of type OperatingSystemOS.

Requirement: optional |
| owner | [User](#ocsf-v1alpha-User) | optional | Description: The identity of the service or user account that owns the endpoint or was last logged into it.

Data Type: A message field of type User.

Requirement: recommended |
| port | [int32](#int32) | optional | Description: The port used for communication within the network connection.

Data Type: The TCP/UDP port number. For example:80,22.

Requirement: recommended |
| proxy_endpoint | [NetworkProxyEndpoint](#ocsf-v1alpha-NetworkProxyEndpoint) | optional | Description: The network proxy information pertaining to a specific endpoint. This can be used to describe information pertaining to network address translation (NAT).

Data Type: A message field of type NetworkProxyEndpoint.

Requirement: optional |
| subnet_uid | [string](#string) | optional | Description: The unique identifier of a virtual subnet.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| svc_name | [string](#string) | optional | Description: The service name in service-to-service connections. For example, AWS VPC logs the pkt-src-aws-service and pkt-dst-aws-service fields identify the connection is coming from or going to an AWS service.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| type | [string](#string) | optional | Description: The network endpoint type. For example: unknown, server, desktop, laptop, tablet, mobile, virtual, browser, or other.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [NetworkEndpointTypeID](#ocsf-v1alpha-NetworkEndpointTypeID) | optional | Description: The network endpoint type ID.

Data Type: An enum field of type NetworkEndpointTypeID.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the endpoint.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vlan_uid | [string](#string) | optional | Description: The Virtual LAN identifier.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| vpc_uid | [string](#string) | optional | Description: The unique identifier of the Virtual Private Cloud (VPC).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| zone | [string](#string) | optional | Description: The network zone or LAN segment.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-NetworkTraffic"></a>

### NetworkTraffic
The Network Traffic object describes characteristics of network traffic.
Network traffic refers to data moving across a network at a given point of
time.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| bytes | [int64](#int64) | optional | Description: The total number of bytes (in and out).

Data Type: 8-byte long, signed integer value.

Requirement: recommended |
| bytes_in | [int64](#int64) | optional | Description: The number of bytes sent from the destination to the source.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| bytes_missed | [int64](#int64) | optional | Description: Indicates the number of bytes missed, which is representative of packet loss.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| bytes_out | [int64](#int64) | optional | Description: The number of bytes sent from the source to the destination.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| chunks | [int64](#int64) | optional | Description: The total number of chunks (in and out).

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| chunks_in | [int64](#int64) | optional | Description: The number of chunks sent from the destination to the source.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| chunks_out | [int64](#int64) | optional | Description: The number of chunks sent from the source to the destination.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| packets | [int64](#int64) | optional | Description: The total number of packets (in and out).

Data Type: 8-byte long, signed integer value.

Requirement: recommended |
| packets_in | [int64](#int64) | optional | Description: The number of packets sent from the destination to the source.

Data Type: 8-byte long, signed integer value.

Requirement: optional |
| packets_out | [int64](#int64) | optional | Description: The number of packets sent from the source to the destination.

Data Type: 8-byte long, signed integer value.

Requirement: optional |






<a name="ocsf-v1alpha-Object"></a>

### Object
An unordered collection of attributes. It defines a set of attributes
available in all objects. It can be also used as a generic object to log
objects that are not otherwise defined by the schema.






<a name="ocsf-v1alpha-Observable"></a>

### Observable
The observable object is a pivot element that contains related information
found in many places in the event.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The full name of the observable attribute. The name is a pointer/reference to an attribute within the OCSF event data. For example: file.name.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| reputation | [Reputation](#ocsf-v1alpha-Reputation) | optional | Description: Contains the original and normalized reputation scores.

Data Type: A message field of type Reputation.

Requirement: optional |
| type | [string](#string) | optional | Description: The observable value type name.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [ObservableTypeID](#ocsf-v1alpha-ObservableTypeID) |  | Description: The observable value type identifier.

Data Type: An enum field of type ObservableTypeID.

Requirement: required |
| value | [string](#string) | optional | Description: The value associated with the observable attribute. The meaning of the value depends on the observable type.If the name refers to a scalar attribute, then the value is the value of the attribute.If the name refers to an object attribute, then the value is not populated.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-OperatingSystemOS"></a>

### OperatingSystemOS
The Operating System (OS) object describes characteristics of an OS, such as
Linux or Windows.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| build | [string](#string) | optional | Description: The operating system build number.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| country | [string](#string) | optional | Description: The operating system country code, as defined by the ISO 3166-1 standard (Alpha-2 code).Note: The two letter country code should be capitalized. For example: US or CA.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cpe_name | [string](#string) | optional | Description: The Common Platform Enumeration (CPE) name as described by (NIST) For example: cpe:/a:apple:safari:16.2.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| cpu_bits | [int32](#int32) | optional | Description: The cpu architecture, the number of bits used for addressing in memory. For example: 32 or 64.

Data Type: Signed integer value.

Requirement: optional |
| edition | [string](#string) | optional | Description: The operating system edition. For example: Professional.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| kernel_release | [string](#string) | optional | Description: The kernel release of the operating system. On Unix-based systems, this is determined from the uname -r command output, for example &#34;5.15.0-122-generic&#34;.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| lang | [string](#string) | optional | Description: The two letter lower case language codes, as defined by ISO 639-1. For example: en (English), de (German), or fr (French).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) |  | Description: The operating system name.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| sp_name | [string](#string) | optional | Description: The name of the latest Service Pack.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| sp_ver | [int32](#int32) | optional | Description: The version number of the latest Service Pack.

Data Type: Signed integer value.

Requirement: optional |
| type | [string](#string) | optional | Description: The type of the operating system.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [OperatingSystemOSTypeID](#ocsf-v1alpha-OperatingSystemOSTypeID) |  | Description: The type identifier of the operating system.

Data Type: An enum field of type OperatingSystemOSTypeID.

Requirement: required |
| version | [string](#string) | optional | Description: The version of the OS running on the device that originated the event. For example: &#34;Windows 10&#34;, &#34;OS X 10.7&#34;, or &#34;iOS 9&#34;.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Organization"></a>

### Organization
The Organization object describes characteristics of an organization or
company and its division if any. Additionally, it also describes cloud and
Software-as-a-Service (SaaS) logical hierarchies such as AWS Organizations,
Google Cloud Organizations, Oracle Cloud Tenancies, and similar constructs.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) | optional | Description: The name of the organization, Oracle Cloud Tenancy, Google Cloud Organization, or AWS Organization. For example, Widget, Inc. or the AWS Organization name .

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| ou_name | [string](#string) | optional | Description: The name of an organizational unit, Google Cloud Folder, or AWS Org Unit. For example, the GCP Project Name , or Dev_Prod_OU .

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| ou_uid | [string](#string) | optional | Description: The unique identifier of an organizational unit, Google Cloud Folder, or AWS Org Unit. For example, an Oracle Cloud Tenancy ID , AWS OU ID , or GCP Folder ID .

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the organization, Oracle Cloud Tenancy, Google Cloud Organization, or AWS Organization. For example, an AWS Org ID or Oracle Cloud Domain ID .

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Policy"></a>

### Policy
The Policy object describes the policies that are applicable. Policy
attributes provide traceability to the operational state of the security
product at the time that the event was captured, facilitating forensics,
troubleshooting, and policy tuning/adjustments.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| desc | [string](#string) | optional | Description: The description of the policy.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| group | [Group](#ocsf-v1alpha-Group) | optional | Description: The policy group.

Data Type: A message field of type Group.

Requirement: optional |
| is_applied | [bool](#bool) | optional | Description: A determination if the content of a policy was applied to a target or request, or not.

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| name | [string](#string) | optional | Description: The policy name. For example: IAM Policy.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: A unique identifier of the policy instance.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: The policy version number.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-Process"></a>

### Process
The Process object describes a running instance of a launched program.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| ancestry | [ProcessEntity](#ocsf-v1alpha-ProcessEntity) | repeated | Description: An array of Process Entities describing the extended parentage of this process object. Direct parent information sould be expressed through the parent_process attribute. The first array element is the direct parent of this process object. Subsequent list elements go up the process parentage hierarchy. That is, the array is sorted from newest to oldest process. It is recommended to only populate this field for the top-level process object.

Data Type: A message field of type ProcessEntity.

Requirement: optional |
| auid | [int32](#int32) | optional | Description: The audit user assigned at login by the audit subsystem.

Data Type: Signed integer value.

Requirement: optional |
| cmd_line | [string](#string) | optional | Description: The full command line used to launch an application, service, process, or job. For example: ssh user@10.0.0.10. If the command line is unavailable or missing, the empty string &#39;&#39; is to be used.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| created_time | [int64](#int64) | optional | Description: The time when the process was created/started.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The time when the process was created/started.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| egid | [int32](#int32) | optional | Description: The effective group under which this process is running.

Data Type: Signed integer value.

Requirement: optional |
| environment_variables | [EnvironmentVariable](#ocsf-v1alpha-EnvironmentVariable) | repeated | Description: Environment variables associated with the process.

Data Type: A message field of type EnvironmentVariable.

Requirement: optional |
| euid | [int32](#int32) | optional | Description: The effective user under which this process is running.

Data Type: Signed integer value.

Requirement: optional |
| file | [File](#ocsf-v1alpha-File) | optional | Description: The process file object.

Data Type: A message field of type File.

Requirement: recommended |
| group | [Group](#ocsf-v1alpha-Group) | optional | Description: The group under which this process is running.

Data Type: A message field of type Group.

Requirement: recommended |
| integrity | [string](#string) | optional | Description: The process integrity level, normalized to the caption of the integrity_id value. In the case of &#39;Other&#39;, it is defined by the event source (Windows only).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| integrity_id | [ProcessIntegrityLevel](#ocsf-v1alpha-ProcessIntegrityLevel) | optional | Description: The normalized identifier of the process integrity level (Windows only).

Data Type: An enum field of type ProcessIntegrityLevel.

Requirement: optional |
| lineage | [string](#string) | repeated | Description: The lineage of the process, represented by a list of paths for each ancestor process. For example: [&#39;/usr/sbin/sshd&#39;, &#39;/usr/bin/bash&#39;, &#39;/usr/bin/whoami&#39;].

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| loaded_modules | [string](#string) | repeated | Description: The list of loaded module names.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The friendly name of the process, for example: Notepad&#43;&#43;.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| parent_process | [Process](#ocsf-v1alpha-Process) | optional | Description: The parent process of this process object. It is recommended to only populate this field for the top-level process object, to prevent deep nesting. Additional ancestry information can be supplied in the ancestry attribute.

Data Type: A message field of type Process.

Requirement: recommended |
| path | [string](#string) | optional | Description: The process file path.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| pid | [int32](#int32) | optional | Description: The process identifier, as reported by the operating system. Process ID (PID) is a number used by the operating system to uniquely identify an active process.

Data Type: Signed integer value.

Requirement: recommended |
| sandbox | [string](#string) | optional | Description: The name of the containment jail (i.e., sandbox). For example, hardened_ps, high_security_ps, oracle_ps, netsvcs_ps, or default_ps.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| session | [Session](#ocsf-v1alpha-Session) | optional | Description: The user session under which this process is running.

Data Type: A message field of type Session.

Requirement: optional |
| terminated_time | [int64](#int64) | optional | Description: The time when the process was terminated.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| terminated_time_dt | [string](#string) | optional | Description: The time when the process was terminated.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| tid | [int32](#int32) | optional | Description: The Identifier of the thread associated with the event, as returned by the operating system.

Data Type: Signed integer value.

Requirement: optional |
| uid | [string](#string) | optional | Description: A unique identifier for this process assigned by the producer (tool). Facilitates correlation of a process event with other events for that process.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| user | [User](#ocsf-v1alpha-User) | optional | Description: The user under which this process is running.

Data Type: A message field of type User.

Requirement: recommended |
| working_directory | [string](#string) | optional | Description: The working directory of a process.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| xattributes | [Object](#ocsf-v1alpha-Object) | optional | Description: An unordered collection of zero or more name/value pairs that represent a process extended attribute.

Data Type: A message field of type Object.

Requirement: optional |






<a name="ocsf-v1alpha-ProcessEntity"></a>

### ProcessEntity
The Process Entity object provides critical fields for referencing a process.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cmd_line | [string](#string) | optional | Description: The full command line used to launch an application, service, process, or job. For example: ssh user@10.0.0.10. If the command line is unavailable or missing, the empty string &#39;&#39; is to be used.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| created_time | [int64](#int64) | optional | Description: The time when the process was created/started.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The time when the process was created/started.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| name | [string](#string) | optional | Description: The friendly name of the process, for example: Notepad&#43;&#43;.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| path | [string](#string) | optional | Description: The process file path.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| pid | [int32](#int32) | optional | Description: The process identifier, as reported by the operating system. Process ID (PID) is a number used by the operating system to uniquely identify an active process.

Data Type: Signed integer value.

Requirement: recommended |
| uid | [string](#string) | optional | Description: A unique identifier for this process assigned by the producer (tool). Facilitates correlation of a process event with other events for that process.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-Product"></a>

### Product
The Product object describes characteristics of a software product.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| cpe_name | [string](#string) | optional | Description: The Common Platform Enumeration (CPE) name as described by (NIST) For example: cpe:/a:apple:safari:16.2.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| feature | [Feature](#ocsf-v1alpha-Feature) | optional | Description: The feature that reported the event.

Data Type: A message field of type Feature.

Requirement: optional |
| lang | [string](#string) | optional | Description: The two letter lower case language codes, as defined by ISO 639-1. For example: en (English), de (German), or fr (French).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the product.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| path | [string](#string) | optional | Description: The installation path of the product.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the product.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| url_string | [string](#string) | optional | Description: The URL pointing towards the product.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: The name of the vendor of the product.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| version | [string](#string) | optional | Description: The version of the product, as defined by the event source. For example: 2013.1.3-beta.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-Reputation"></a>

### Reputation
The Reputation object describes the reputation/risk score of an entity (e.g.
device, user, domain).


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| base_score | [float](#float) |  | Description: The reputation score as reported by the event source.

Data Type: Real floating-point value. For example:3.14.

Requirement: required |
| provider | [string](#string) | optional | Description: The provider of the reputation information.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| score | [string](#string) | optional | Description: The reputation score, normalized to the caption of the score_id value. In the case of &#39;Other&#39;, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| score_id | [ReputationReputationScoreID](#ocsf-v1alpha-ReputationReputationScoreID) |  | Description: The normalized reputation score identifier.

Data Type: An enum field of type ReputationReputationScoreID.

Requirement: required |






<a name="ocsf-v1alpha-SCIM"></a>

### SCIM
The System for Cross-domain Identity Management (SCIM) Configuration object
provides a structured set of attributes related to SCIM protocols used for
identity provisioning and management across cloud-based platforms. It
standardizes user and group provisioning details, enabling identity
synchronization and lifecycle management with compatible Identity Providers
(IdPs) and applications. SCIM is defined in RFC-7634


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| auth_protocol | [string](#string) | optional | Description: The authorization protocol as defined by the caption of auth_protocol_id. In the case of Other, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| auth_protocol_id | [SCIMAuthProtocolID](#ocsf-v1alpha-SCIMAuthProtocolID) | optional | Description: The normalized identifier of the authorization protocol used by the SCIM resource.

Data Type: An enum field of type SCIMAuthProtocolID.

Requirement: optional |
| created_time | [int64](#int64) | optional | Description: When the SCIM resource was added to the service provider.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: When the SCIM resource was added to the service provider.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| error_message | [string](#string) | optional | Description: Message or code associated with the last encountered error.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| is_group_provisioning_enabled | [bool](#bool) | optional | Description: Indicates whether the SCIM resource is configured to provision groups, automatically or otherwise.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_user_provisioning_enabled | [bool](#bool) | optional | Description: Indicates whether the SCIM resource is configured to provision users, automatically or otherwise.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| last_run_time | [int64](#int64) | optional | Description: Timestamp of the most recent successful synchronization.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| last_run_time_dt | [string](#string) | optional | Description: Timestamp of the most recent successful synchronization.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The most recent time when the SCIM resource was updated at the service provider.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The most recent time when the SCIM resource was updated at the service provider.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the SCIM resource.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| protocol_name | [string](#string) | optional | Description: The supported protocol for the SCIM resource. E.g., SAML, OIDC, or OAuth2.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| rate_limit | [int32](#int32) | optional | Description: Maximum number of requests allowed by the SCIM resource within a specified time frame to avoid throttling.

Data Type: Signed integer value.

Requirement: optional |
| scim_group_schema | [string](#string) | optional | Description: SCIM provides a schema for representing groups, identified using the following schema URI: urn:ietf:params:scim:schemas:core:2.0:Group as defined in RFC-7634. This attribute will capture key-value pairs for the scheme implemented in a SCIM resource.

Data Type: Embedded JSON value. A value can be a string, or a number, or true or false or null, or an object or an array. These structures can be nested. See www.json.org.

Requirement: recommended |
| scim_user_schema | [string](#string) | optional | Description: SCIM provides a resource type for user resources. The core schema for user is identified using the following schema URI: urn:ietf:params:scim:schemas:core:2.0:User as defined in RFC-7634. his attribute will capture key-value pairs for the scheme implemented in a SCIM resource. This object is inclusive of both the basic and Enterprise User Schema Extension.

Data Type: Embedded JSON value. A value can be a string, or a number, or true or false or null, or an object or an array. These structures can be nested. See www.json.org.

Requirement: recommended |
| state | [string](#string) | optional | Description: The provisioning state of the SCIM resource, normalized to the caption of the state_id value. In the case of Other, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| state_id | [SCIMStateID](#ocsf-v1alpha-SCIMStateID) | optional | Description: The normalized state ID of the SCIM resource to reflect its activation status.

Data Type: An enum field of type SCIMStateID.

Requirement: optional |
| uid | [string](#string) | optional | Description: A unique identifier for a SCIM resource as defined by the service provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid_alt | [string](#string) | optional | Description: A String that is an identifier for the resource as defined by the provisioning client. The externalId may simplify identification of a resource between the provisioning client and the service provider by allowing the client to use a filter to locate the resource with an identifier from the provisioning domain, obviating the need to store a local mapping between the provisioning domain&#39;s identifier of the resource and the identifier used by the service provider.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| url_string | [string](#string) | optional | Description: The primary URL for SCIM API requests.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| vendor_name | [string](#string) | optional | Description: Name of the vendor or service provider implementing SCIM. E.g., Okta, Auth0, Microsoft.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| version | [string](#string) | optional | Description: SCIM protocol version supported e.g., SCIM 2.0.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |






<a name="ocsf-v1alpha-SSO"></a>

### SSO
The Single Sign-On (SSO) object provides a structure for normalizing SSO
attributes, configuration, and/or settings from Identity Providers.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| auth_protocol | [string](#string) | optional | Description: The authorization protocol as defined by the caption of auth_protocol_id. In the case of Other, it is defined by the event source.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| auth_protocol_id | [SSOAuthProtocolID](#ocsf-v1alpha-SSOAuthProtocolID) | optional | Description: The normalized identifier of the authentication protocol used by the SSO resource.

Data Type: An enum field of type SSOAuthProtocolID.

Requirement: optional |
| certificate | [DigitalCertificate](#ocsf-v1alpha-DigitalCertificate) | optional | Description: Digital Signature associated with the SSO resource, e.g., SAML X.509 certificate details.

Data Type: A message field of type DigitalCertificate.

Requirement: recommended |
| created_time | [int64](#int64) | optional | Description: When the SSO resource was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| created_time_dt | [string](#string) | optional | Description: When the SSO resource was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| duration_mins | [int32](#int32) | optional | Description: The duration (in minutes) for an SSO session, after which re- authentication is required.

Data Type: Signed integer value.

Requirement: optional |
| idle_timeout | [int32](#int32) | optional | Description: Duration (in minutes) of allowed inactivity before Single Sign-On (SSO) session expiration.

Data Type: Signed integer value.

Requirement: optional |
| login_endpoint | [string](#string) | optional | Description: URL for initiating an SSO login request.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| logout_endpoint | [string](#string) | optional | Description: URL for initiating an SSO logout request, allowing sessions to be terminated across applications.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| metadata_endpoint | [string](#string) | optional | Description: URL where metadata about the SSO configuration is available (e.g., for SAML configurations).

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: optional |
| modified_time | [int64](#int64) | optional | Description: The most recent time when the SSO resource was updated.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| modified_time_dt | [string](#string) | optional | Description: The most recent time when the SSO resource was updated.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| name | [string](#string) | optional | Description: The name of the SSO resource.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| protocol_name | [string](#string) | optional | Description: The supported protocol for the SSO resource. E.g., SAML or OIDC.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| scopes | [string](#string) | repeated | Description: Scopes define the specific permissions or actions that the client is allowed to perform on behalf of the user. Each scope represents a different set of permissions, and the user can selectively grant or deny access to specific scopes during the authorization process.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: A unique identifier for a SSO resource.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| vendor_name | [string](#string) | optional | Description: Name of the vendor or service provider implementing SSO. E.g., Okta, Auth0, Microsoft.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |






<a name="ocsf-v1alpha-SchemaExtension"></a>

### SchemaExtension
The OCSF Schema Extension object provides detailed information about the
schema extension used to construct the event. The schema extensions are
registered in the extensions.md file.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Description: The schema extension name. For example: dev.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| uid | [string](#string) |  | Description: The schema extension unique identifier. For example: 999.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| version | [string](#string) |  | Description: The schema extension version. For example: 1.0.0-alpha.2.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-Session"></a>

### Session
The Session object describes details about an authenticated session. e.g.
Session Creation Time, Session Issuer.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| count | [int32](#int32) | optional | Description: The number of identical sessions spawned from the same source IP, destination IP, application, and content/threat type seen over a period of time.

Data Type: Signed integer value.

Requirement: optional |
| created_time | [int64](#int64) | optional | Description: The time when the session was created.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: recommended |
| created_time_dt | [string](#string) | optional | Description: The time when the session was created.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| credential_uid | [string](#string) | optional | Description: The unique identifier of the user&#39;s credential. For example, AWS Access Key ID.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| expiration_reason | [string](#string) | optional | Description: The reason which triggered the session expiration.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| expiration_time | [int64](#int64) | optional | Description: The session expiration time.

Data Type: The timestamp format is the number of milliseconds since the Epoch 01/01/1970 00:00:00 UTC. For example:1618524549901.

Requirement: optional |
| expiration_time_dt | [string](#string) | optional | Description: The session expiration time.

Data Type: The Internet Date/Time format as defined in RFC-3339. For example:2024-09-10T23:20:50.520Z,2024-09-10 23:20:50.520789Z.

Requirement: optional |
| is_mfa | [bool](#bool) | optional | Description: Indicates whether Multi Factor Authentication was used during authentication.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| is_remote | [bool](#bool) | optional | Description: The indication of whether the session is remote.

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| is_vpn | [bool](#bool) | optional | Description: The indication of whether the session is a VPN session.

Data Type: Boolean value. One of true or false.

Requirement: optional |
| issuer | [string](#string) | optional | Description: The identifier of the session issuer.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| terminal | [string](#string) | optional | Description: The Pseudo Terminal associated with the session. Ex: the tty or pts value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uid | [string](#string) | optional | Description: The unique identifier of the session.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid_alt | [string](#string) | optional | Description: The alternate unique identifier of the session. e.g. AWS ARN - arn:aws:sts::123344444444:assumed-role/Admin/example-session.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| uuid | [string](#string) | optional | Description: The universally unique identifier of the session.

Data Type: 128-bit universal unique identifier. For example:123e4567-e89b-12d3-a456-42661417400.

Requirement: optional |






<a name="ocsf-v1alpha-SubjectAlternativeName"></a>

### SubjectAlternativeName
The Subject Alternative name (SAN) object describes a SAN secured by a
digital certificate


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| name | [string](#string) |  | Description: Name of SAN (e.g. The actual IP Address or domain.)

Data Type: UTF-8 encoded byte sequence.

Requirement: required |
| type | [string](#string) |  | Description: Type descriptor of SAN (e.g. IP Address/domain/etc.)

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-TLSExtension"></a>

### TLSExtension
The TLS Extension object describes additional attributes that extend the base
Transport Layer Security (TLS) object.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| data | [string](#string) | optional | Description: The data contains information specific to the particular extension type.

Data Type: Embedded JSON value. A value can be a string, or a number, or true or false or null, or an object or an array. These structures can be nested. See www.json.org.

Requirement: recommended |
| type | [string](#string) | optional | Description: The TLS extension type. For example: Server Name.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [TLSExtensionTypeID](#ocsf-v1alpha-TLSExtensionTypeID) |  | Description: The TLS extension type identifier. See The Transport Layer Security (TLS) extension page.

Data Type: An enum field of type TLSExtensionTypeID.

Requirement: required |






<a name="ocsf-v1alpha-TransportLayerSecurityTLS"></a>

### TransportLayerSecurityTLS
The Transport Layer Security (TLS) object describes the negotiated TLS
protocol used for secure communications over an establish network connection.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| alert | [int32](#int32) | optional | Description: The integer value of TLS alert if present. The alerts are defined in the TLS specification in RFC-2246.

Data Type: Signed integer value.

Requirement: optional |
| certificate | [DigitalCertificate](#ocsf-v1alpha-DigitalCertificate) | optional | Description: The certificate object containing information about the digital certificate.

Data Type: A message field of type DigitalCertificate.

Requirement: recommended |
| certificate_chain | [string](#string) | repeated | Description: The Chain of Certificate Serial Numbers field provides a chain of Certificate Issuer Serial Numbers leading to the Root Certificate Issuer.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| cipher | [string](#string) | optional | Description: The negotiated cipher suite.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| client_ciphers | [string](#string) | repeated | Description: The client cipher suites that were exchanged during the TLS handshake negotiation.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| extension_list | [TLSExtension](#ocsf-v1alpha-TLSExtension) | repeated | Description: The list of TLS extensions.

Data Type: A message field of type TLSExtension.

Requirement: optional |
| handshake_dur | [int32](#int32) | optional | Description: The amount of total time for the TLS handshake to complete after the TCP connection is established, including client-side delays, in milliseconds.

Data Type: Signed integer value.

Requirement: optional |
| ja3_hash | [Fingerprint](#ocsf-v1alpha-Fingerprint) | optional | Description: The MD5 hash of a JA3 string.

Data Type: A message field of type Fingerprint.

Requirement: recommended |
| ja3s_hash | [Fingerprint](#ocsf-v1alpha-Fingerprint) | optional | Description: The MD5 hash of a JA3S string.

Data Type: A message field of type Fingerprint.

Requirement: recommended |
| key_length | [int32](#int32) | optional | Description: The length of the encryption key.

Data Type: Signed integer value.

Requirement: optional |
| sans | [SubjectAlternativeName](#ocsf-v1alpha-SubjectAlternativeName) | repeated | Description: The list of subject alternative names that are secured by a specific certificate.

Data Type: A message field of type SubjectAlternativeName.

Requirement: optional |
| server_ciphers | [string](#string) | repeated | Description: The server cipher suites that were exchanged during the TLS handshake negotiation.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| sni | [string](#string) | optional | Description: The Server Name Indication (SNI) extension sent by the client.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| tls_extension_list | [TLSExtension](#ocsf-v1alpha-TLSExtension) | repeated | Description: The list of TLS extensions.

Data Type: A message field of type TLSExtension.

Requirement: optional |
| version | [string](#string) |  | Description: The TLS protocol version.

Data Type: UTF-8 encoded byte sequence.

Requirement: required |






<a name="ocsf-v1alpha-UniformResourceLocator"></a>

### UniformResourceLocator
The Uniform Resource Locator (URL) object describes the characteristics of a
URL.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| categories | [string](#string) | repeated | Description: The Website categorization names, as defined by category_ids enum values.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| category_ids | [UniformResourceLocatorWebsiteCategorizationIDs](#ocsf-v1alpha-UniformResourceLocatorWebsiteCategorizationIDs) | repeated | Description: The Website categorization identifiers.

Data Type: An enum field of type UniformResourceLocatorWebsiteCategorizationIDs.

Requirement: recommended |
| domain | [string](#string) | optional | Description: The domain portion of the URL. For example: example.com in https://sub.example.com.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| hostname | [string](#string) | optional | Description: The URL host as extracted from the URL. For example: www.example.com from www.example.com/download/trouble.

Data Type: Unique name assigned to a device connected to a computer network. It may be a fully qualified domain name (FQDN). For example:r2-d2.example.com.,mx.example.com

Requirement: recommended |
| path | [string](#string) | optional | Description: The URL path as extracted from the URL. For example: /download/trouble from www.example.com/download/trouble.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| port | [int32](#int32) | optional | Description: The URL port. For example: 80.

Data Type: The TCP/UDP port number. For example:80,22.

Requirement: recommended |
| query_string | [string](#string) | optional | Description: The query portion of the URL. For example: the query portion of the URL http://www.example.com/search?q=bad&amp;sort=date is q=bad&amp;sort=date.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| resource_type | [string](#string) | optional | Description: The context in which a resource was retrieved in a web request.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| scheme | [string](#string) | optional | Description: The scheme portion of the URL. For example: http, https, ftp, or sftp.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| subdomain | [string](#string) | optional | Description: The subdomain portion of the URL. For example: sub in https://sub.example.com or sub2.sub1 in https://sub2.sub1.example.com.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| url_string | [string](#string) | optional | Description: The URL string. See RFC 1738. For example: http://www.example.com/download/trouble.exe. Note: The URL path should not populate the URL string.

Data Type: Uniform Resource Locator (URL) string. For example:http://www.example.com/download/trouble.exe.

Requirement: recommended |






<a name="ocsf-v1alpha-User"></a>

### User
The User object describes the characteristics of a user/person or a security
principal.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| account | [Account](#ocsf-v1alpha-Account) | optional | Description: The user&#39;s account or the account associated with the user.

Data Type: A message field of type Account.

Requirement: optional |
| credential_uid | [string](#string) | optional | Description: The unique identifier of the user&#39;s credential. For example, AWS Access Key ID.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| domain | [string](#string) | optional | Description: The domain where the user is defined. For example: the LDAP or Active Directory domain.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| email_addr | [string](#string) | optional | Description: The user&#39;s primary email address.

Data Type: Email address. For example:john_doe@example.com.

Requirement: optional |
| forward_addr | [string](#string) | optional | Description: The user&#39;s forwarding email address.

Data Type: Email address. For example:john_doe@example.com.

Requirement: optional |
| full_name | [string](#string) | optional | Description: The full name of the person, as per the LDAP Common Name attribute (cn).

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| groups | [Group](#ocsf-v1alpha-Group) | repeated | Description: The administrative groups to which the user belongs.

Data Type: A message field of type Group.

Requirement: optional |
| has_mfa | [bool](#bool) | optional | Description: The user has a multi-factor or secondary-factor device assigned.

Data Type: Boolean value. One of true or false.

Requirement: recommended |
| ldap_person | [LDAPPerson](#ocsf-v1alpha-LDAPPerson) | optional | Description: The additional LDAP attributes that describe a person.

Data Type: A message field of type LDAPPerson.

Requirement: optional |
| name | [string](#string) | optional | Description: The username. For example, janedoe1.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| org | [Organization](#ocsf-v1alpha-Organization) | optional | Description: Organization and org unit related to the user.

Data Type: A message field of type Organization.

Requirement: optional |
| phone_number | [string](#string) | optional | Description: The telephone number of the user.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_level | [string](#string) | optional | Description: The risk level, normalized to the caption of the risk_level_id value.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| risk_level_id | [UserRiskLevelID](#ocsf-v1alpha-UserRiskLevelID) | optional | Description: The normalized risk level id.

Data Type: An enum field of type UserRiskLevelID.

Requirement: optional |
| risk_score | [int32](#int32) | optional | Description: The risk score as reported by the event source.

Data Type: Signed integer value.

Requirement: optional |
| type | [string](#string) | optional | Description: The type of the user. For example, System, AWS IAM User, etc.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |
| type_id | [UserTypeID](#ocsf-v1alpha-UserTypeID) | optional | Description: The account type identifier.

Data Type: An enum field of type UserTypeID.

Requirement: recommended |
| uid | [string](#string) | optional | Description: The unique user identifier. For example, the Windows user SID, ActiveDirectory DN or AWS user ARN.

Data Type: UTF-8 encoded byte sequence.

Requirement: recommended |
| uid_alt | [string](#string) | optional | Description: The alternate user identifier. For example, the Active Directory user GUID or AWS user Principal ID.

Data Type: UTF-8 encoded byte sequence.

Requirement: optional |





 


<a name="ocsf-v1alpha-AccountTypeID"></a>

### AccountTypeID
The normalized account type identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| ACCOUNT_TYPE_ID_UNKNOWN | 0 |  |
| ACCOUNT_TYPE_ID_LDAP_ACCOUNT | 1 |  |
| ACCOUNT_TYPE_ID_WINDOWS_ACCOUNT | 2 |  |
| ACCOUNT_TYPE_ID_AWS_IAM_USER | 3 |  |
| ACCOUNT_TYPE_ID_AWS_IAM_ROLE | 4 |  |
| ACCOUNT_TYPE_ID_GCP_ACCOUNT | 5 |  |
| ACCOUNT_TYPE_ID_AZURE_AD_ACCOUNT | 6 |  |
| ACCOUNT_TYPE_ID_MAC_OS_ACCOUNT | 7 |  |
| ACCOUNT_TYPE_ID_APPLE_ACCOUNT | 8 |  |
| ACCOUNT_TYPE_ID_LINUX_ACCOUNT | 9 |  |
| ACCOUNT_TYPE_ID_AWS_ACCOUNT | 10 |  |
| ACCOUNT_TYPE_ID_GCP_PROJECT | 11 |  |
| ACCOUNT_TYPE_ID_OCI_COMPARTMENT | 12 |  |
| ACCOUNT_TYPE_ID_AZURE_SUBSCRIPTION | 13 |  |
| ACCOUNT_TYPE_ID_SALESFORCE_ACCOUNT | 14 |  |
| ACCOUNT_TYPE_ID_GOOGLE_WORKSPACE | 15 |  |
| ACCOUNT_TYPE_ID_SERVICENOW_INSTANCE | 16 |  |
| ACCOUNT_TYPE_ID_M365_TENANT | 17 |  |
| ACCOUNT_TYPE_ID_EMAIL_ACCOUNT | 18 |  |
| ACCOUNT_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-AgentTypeID"></a>

### AgentTypeID
The normalized representation of an agent or sensor. E.g., EDR, vulnerability
management, APM, backup &amp; recovery, etc.

| Name | Number | Description |
| ---- | ------ | ----------- |
| AGENT_TYPE_ID_UNKNOWN | 0 |  |
| AGENT_TYPE_ID_ENDPOINT_DETECTION_AND_RESPONSE | 1 |  |
| AGENT_TYPE_ID_DATA_LOSS_PREVENTION | 2 |  |
| AGENT_TYPE_ID_BACKUP_AND_RECOVERY | 3 |  |
| AGENT_TYPE_ID_PERFORMANCE_MONITORING_AND_OBSERVABILITY | 4 |  |
| AGENT_TYPE_ID_VULNERABILITY_MANAGEMENT | 5 |  |
| AGENT_TYPE_ID_LOG_FORWARDING | 6 |  |
| AGENT_TYPE_ID_MOBILE_DEVICE_MANAGEMENT | 7 |  |
| AGENT_TYPE_ID_CONFIGURATION_MANAGEMENT | 8 |  |
| AGENT_TYPE_ID_REMOTE_ACCESS | 9 |  |
| AGENT_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-AuthenticationFactorFactorTypeID"></a>

### AuthenticationFactorFactorTypeID
The normalized identifier for the authentication factor.

| Name | Number | Description |
| ---- | ------ | ----------- |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_UNKNOWN | 0 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_SMS | 1 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_SECURITY_QUESTION | 2 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_PHONE_CALL | 3 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_BIOMETRIC | 4 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_PUSH_NOTIFICATION | 5 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_HARDWARE_TOKEN | 6 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_OTP | 7 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_EMAIL | 8 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_U2F | 9 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_WEBAUTHN | 10 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_PASSWORD | 11 |  |
| AUTHENTICATION_FACTOR_FACTOR_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-BaseEventSeverityID"></a>

### BaseEventSeverityID
The normalized identifier of the event/finding severity.The normalized
severity is a measurement the effort and expense required to manage and
resolve an event or incident. Smaller numerical values represent lower impact
events, and larger numerical values represent higher impact events.

| Name | Number | Description |
| ---- | ------ | ----------- |
| BASE_EVENT_SEVERITY_ID_UNKNOWN | 0 |  |
| BASE_EVENT_SEVERITY_ID_INFORMATIONAL | 1 |  |
| BASE_EVENT_SEVERITY_ID_LOW | 2 |  |
| BASE_EVENT_SEVERITY_ID_MEDIUM | 3 |  |
| BASE_EVENT_SEVERITY_ID_HIGH | 4 |  |
| BASE_EVENT_SEVERITY_ID_CRITICAL | 5 |  |
| BASE_EVENT_SEVERITY_ID_FATAL | 6 |  |
| BASE_EVENT_SEVERITY_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-BaseEventStatusID"></a>

### BaseEventStatusID
The normalized identifier of the event status.

| Name | Number | Description |
| ---- | ------ | ----------- |
| BASE_EVENT_STATUS_ID_UNKNOWN | 0 |  |
| BASE_EVENT_STATUS_ID_SUCCESS | 1 |  |
| BASE_EVENT_STATUS_ID_FAILURE | 2 |  |
| BASE_EVENT_STATUS_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-CategoryID"></a>

### CategoryID
The OCSF categories organize event classes, each aligned with a specific
domain or area of focus.

| Name | Number | Description |
| ---- | ------ | ----------- |
| CATEGORY_ID_UNCATEGORIZED | 0 |  |
| CATEGORY_ID_APPLICATION_ACTIVITY | 6 |  |
| CATEGORY_ID_DISCOVERY | 5 |  |
| CATEGORY_ID_FINDINGS | 2 |  |
| CATEGORY_ID_IDENTITY_AND_ACCESS_MANAGEMENT | 3 |  |
| CATEGORY_ID_NETWORK_ACTIVITY | 4 |  |
| CATEGORY_ID_REMEDIATION | 7 |  |
| CATEGORY_ID_SYSTEM_ACTIVITY | 1 |  |
| CATEGORY_ID_UNMANNED_SYSTEMS | 8 |  |
| CATEGORY_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-ClassID"></a>

### ClassID
The OCSF event classes.

| Name | Number | Description |
| ---- | ------ | ----------- |
| CLASS_ID_BASE_EVENT | 0 |  |
| CLASS_ID_OTHER | 99 |  |
| CLASS_ID_NETWORK_ACTIVITY | 4001 |  |



<a name="ocsf-v1alpha-DeviceHardwareInfoCPUArchitectureID"></a>

### DeviceHardwareInfoCPUArchitectureID
The normalized identifier of the CPU architecture.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_UNKNOWN | 0 |  |
| DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_X86 | 1 |  |
| DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_ARM | 2 |  |
| DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_RISC_V | 3 |  |
| DEVICE_HARDWARE_INFO_CPUARCHITECTURE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-DeviceRiskLevelID"></a>

### DeviceRiskLevelID
The normalized risk level id.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DEVICE_RISK_LEVEL_ID_INFO | 0 |  |
| DEVICE_RISK_LEVEL_ID_LOW | 1 |  |
| DEVICE_RISK_LEVEL_ID_MEDIUM | 2 |  |
| DEVICE_RISK_LEVEL_ID_HIGH | 3 |  |
| DEVICE_RISK_LEVEL_ID_CRITICAL | 4 |  |
| DEVICE_RISK_LEVEL_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-DeviceTypeID"></a>

### DeviceTypeID
The device type ID.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DEVICE_TYPE_ID_UNKNOWN | 0 |  |
| DEVICE_TYPE_ID_SERVER | 1 |  |
| DEVICE_TYPE_ID_DESKTOP | 2 |  |
| DEVICE_TYPE_ID_LAPTOP | 3 |  |
| DEVICE_TYPE_ID_TABLET | 4 |  |
| DEVICE_TYPE_ID_MOBILE | 5 |  |
| DEVICE_TYPE_ID_VIRTUAL | 6 |  |
| DEVICE_TYPE_ID_IOT | 7 |  |
| DEVICE_TYPE_ID_BROWSER | 8 |  |
| DEVICE_TYPE_ID_FIREWALL | 9 |  |
| DEVICE_TYPE_ID_SWITCH | 10 |  |
| DEVICE_TYPE_ID_HUB | 11 |  |
| DEVICE_TYPE_ID_ROUTER | 12 |  |
| DEVICE_TYPE_ID_IDS | 13 |  |
| DEVICE_TYPE_ID_IPS | 14 |  |
| DEVICE_TYPE_ID_LOAD_BALANCER | 15 |  |
| DEVICE_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-DigitalSignatureAlgorithmID"></a>

### DigitalSignatureAlgorithmID
The identifier of the normalized digital signature algorithm.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DIGITAL_SIGNATURE_ALGORITHM_ID_UNKNOWN | 0 |  |
| DIGITAL_SIGNATURE_ALGORITHM_ID_DSA | 1 |  |
| DIGITAL_SIGNATURE_ALGORITHM_ID_RSA | 2 |  |
| DIGITAL_SIGNATURE_ALGORITHM_ID_ECDSA | 3 |  |
| DIGITAL_SIGNATURE_ALGORITHM_ID_AUTHENTICODE | 4 |  |
| DIGITAL_SIGNATURE_ALGORITHM_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-DigitalSignatureStateID"></a>

### DigitalSignatureStateID
The normalized identifier of the signature state.

| Name | Number | Description |
| ---- | ------ | ----------- |
| DIGITAL_SIGNATURE_STATE_ID_UNKNOWN | 0 |  |
| DIGITAL_SIGNATURE_STATE_ID_VALID | 1 |  |
| DIGITAL_SIGNATURE_STATE_ID_EXPIRED | 2 |  |
| DIGITAL_SIGNATURE_STATE_ID_REVOKED | 3 |  |
| DIGITAL_SIGNATURE_STATE_ID_SUSPENDED | 4 |  |
| DIGITAL_SIGNATURE_STATE_ID_PENDING | 5 |  |
| DIGITAL_SIGNATURE_STATE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-EncryptionDetailsAlgorithmID"></a>

### EncryptionDetailsAlgorithmID
The encryption algorithm used.

| Name | Number | Description |
| ---- | ------ | ----------- |
| ENCRYPTION_DETAILS_ALGORITHM_ID_UNKNOWN | 0 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_DES | 1 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_TRIPLEDES | 2 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_AES | 3 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_RSA | 4 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_ECC | 5 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_SM2 | 6 |  |
| ENCRYPTION_DETAILS_ALGORITHM_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-FileConfidentialityID"></a>

### FileConfidentialityID
The normalized identifier of the file content confidentiality indicator.

| Name | Number | Description |
| ---- | ------ | ----------- |
| FILE_CONFIDENTIALITY_ID_UNKNOWN | 0 |  |
| FILE_CONFIDENTIALITY_ID_NOT_CONFIDENTIAL | 1 |  |
| FILE_CONFIDENTIALITY_ID_CONFIDENTIAL | 2 |  |
| FILE_CONFIDENTIALITY_ID_SECRET | 3 |  |
| FILE_CONFIDENTIALITY_ID_TOP_SECRET | 4 |  |
| FILE_CONFIDENTIALITY_ID_PRIVATE | 5 |  |
| FILE_CONFIDENTIALITY_ID_RESTRICTED | 6 |  |
| FILE_CONFIDENTIALITY_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-FileDriveTypeID"></a>

### FileDriveTypeID
Identifies the type of a disk drive, i.e. fixed, removable, etc.

| Name | Number | Description |
| ---- | ------ | ----------- |
| FILE_DRIVE_TYPE_ID_UNKNOWN | 0 |  |
| FILE_DRIVE_TYPE_ID_REMOVABLE | 1 |  |
| FILE_DRIVE_TYPE_ID_FIXED | 2 |  |
| FILE_DRIVE_TYPE_ID_REMOTE | 3 |  |
| FILE_DRIVE_TYPE_ID_CD_ROM | 4 |  |
| FILE_DRIVE_TYPE_ID_RAM_DISK | 5 |  |
| FILE_DRIVE_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-FileTypeID"></a>

### FileTypeID
The file type ID.

| Name | Number | Description |
| ---- | ------ | ----------- |
| FILE_TYPE_ID_UNKNOWN | 0 |  |
| FILE_TYPE_ID_REGULAR_FILE | 1 |  |
| FILE_TYPE_ID_FOLDER | 2 |  |
| FILE_TYPE_ID_CHARACTER_DEVICE | 3 |  |
| FILE_TYPE_ID_BLOCK_DEVICE | 4 |  |
| FILE_TYPE_ID_LOCAL_SOCKET | 5 |  |
| FILE_TYPE_ID_NAMED_PIPE | 6 |  |
| FILE_TYPE_ID_SYMBOLIC_LINK | 7 |  |
| FILE_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-FingerprintAlgorithmID"></a>

### FingerprintAlgorithmID
The identifier of the normalized hash algorithm, which was used to create the
digital fingerprint.

| Name | Number | Description |
| ---- | ------ | ----------- |
| FINGERPRINT_ALGORITHM_ID_UNKNOWN | 0 |  |
| FINGERPRINT_ALGORITHM_ID_MD5 | 1 |  |
| FINGERPRINT_ALGORITHM_ID_SHA_1 | 2 |  |
| FINGERPRINT_ALGORITHM_ID_SHA_256 | 3 |  |
| FINGERPRINT_ALGORITHM_ID_SHA_512 | 4 |  |
| FINGERPRINT_ALGORITHM_ID_CTPH | 5 |  |
| FINGERPRINT_ALGORITHM_ID_TLSH | 6 |  |
| FINGERPRINT_ALGORITHM_ID_QUICKXORHASH | 7 |  |
| FINGERPRINT_ALGORITHM_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-IdentityProviderStateID"></a>

### IdentityProviderStateID
The normalized state ID of the Identity Provider to reflect its configuration
or activation status.

| Name | Number | Description |
| ---- | ------ | ----------- |
| IDENTITY_PROVIDER_STATE_ID_UNKNOWN | 0 |  |
| IDENTITY_PROVIDER_STATE_ID_ACTIVE | 1 |  |
| IDENTITY_PROVIDER_STATE_ID_SUSPENDED | 2 |  |
| IDENTITY_PROVIDER_STATE_ID_DEPRECATED | 3 |  |
| IDENTITY_PROVIDER_STATE_ID_DELETED | 4 |  |
| IDENTITY_PROVIDER_STATE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-JA4FingerprintTypeID"></a>

### JA4FingerprintTypeID
The identifier of the JA4&#43; fingerprint type.

| Name | Number | Description |
| ---- | ------ | ----------- |
| JA4_FINGERPRINT_TYPE_ID_UNKNOWN | 0 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4 | 1 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4SERVER | 2 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4HTTP | 3 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4LATENCY | 4 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4X509 | 5 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4SSH | 6 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4TCP | 7 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4TCPSERVER | 8 |  |
| JA4_FINGERPRINT_TYPE_ID_JA4TCPSCAN | 9 |  |
| JA4_FINGERPRINT_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-MalwareClassificationIDs"></a>

### MalwareClassificationIDs
The list of normalized identifiers of the malware classifications. Reference:
STIX Malware Types

| Name | Number | Description |
| ---- | ------ | ----------- |
| MALWARE_CLASSIFICATION_IDS_UNKNOWN | 0 |  |
| MALWARE_CLASSIFICATION_IDS_ADWARE | 1 |  |
| MALWARE_CLASSIFICATION_IDS_BACKDOOR | 2 |  |
| MALWARE_CLASSIFICATION_IDS_BOT | 3 |  |
| MALWARE_CLASSIFICATION_IDS_BOOTKIT | 4 |  |
| MALWARE_CLASSIFICATION_IDS_DDOS | 5 |  |
| MALWARE_CLASSIFICATION_IDS_DOWNLOADER | 6 |  |
| MALWARE_CLASSIFICATION_IDS_DROPPER | 7 |  |
| MALWARE_CLASSIFICATION_IDS_EXPLOIT_KIT | 8 |  |
| MALWARE_CLASSIFICATION_IDS_KEYLOGGER | 9 |  |
| MALWARE_CLASSIFICATION_IDS_RANSOMWARE | 10 |  |
| MALWARE_CLASSIFICATION_IDS_REMOTE_ACCESS_TROJAN | 11 |  |
| MALWARE_CLASSIFICATION_IDS_RESOURCE_EXPLOITATION | 13 |  |
| MALWARE_CLASSIFICATION_IDS_ROGUE_SECURITY_SOFTWARE | 14 |  |
| MALWARE_CLASSIFICATION_IDS_ROOTKIT | 15 |  |
| MALWARE_CLASSIFICATION_IDS_SCREEN_CAPTURE | 16 |  |
| MALWARE_CLASSIFICATION_IDS_SPYWARE | 17 |  |
| MALWARE_CLASSIFICATION_IDS_TROJAN | 18 |  |
| MALWARE_CLASSIFICATION_IDS_VIRUS | 19 |  |
| MALWARE_CLASSIFICATION_IDS_WEBSHELL | 20 |  |
| MALWARE_CLASSIFICATION_IDS_WIPER | 21 |  |
| MALWARE_CLASSIFICATION_IDS_WORM | 22 |  |
| MALWARE_CLASSIFICATION_IDS_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkActivityActivityID"></a>

### NetworkActivityActivityID
The normalized identifier of the activity that triggered the event.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_ACTIVITY_ACTIVITY_ID_UNKNOWN | 0 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_OPEN | 1 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_CLOSE | 2 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_RESET | 3 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_FAIL | 4 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_REFUSE | 5 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_TRAFFIC | 6 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_LISTEN | 7 |  |
| NETWORK_ACTIVITY_ACTIVITY_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkConnectionInformationBoundaryID"></a>

### NetworkConnectionInformationBoundaryID
The normalized identifier of the boundary of the connection.  For cloud
connections, this translates to the traffic-boundary (same VPC, through IGW,
etc.). For traditional networks, this is described as Local, Internal, or
External.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_UNKNOWN | 0 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_LOCALHOST | 1 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_INTERNAL | 2 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_EXTERNAL | 3 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_SAME_VPC | 4 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_INTERNET_OR_VPC_GATEWAY | 5 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_VIRTUAL_PRIVATE_GATEWAY | 6 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_INTRA_REGION_VPC | 7 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_INTER_REGION_VPC | 8 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_LOCAL_GATEWAY | 9 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_GATEWAY_VPC | 10 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_INTERNET_GATEWAY | 11 |  |
| NETWORK_CONNECTION_INFORMATION_BOUNDARY_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkConnectionInformationDirectionID"></a>

### NetworkConnectionInformationDirectionID
The normalized identifier of the direction of the initiated connection,
traffic, or email.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_UNKNOWN | 0 |  |
| NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_INBOUND | 1 |  |
| NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_OUTBOUND | 2 |  |
| NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_LATERAL | 3 |  |
| NETWORK_CONNECTION_INFORMATION_DIRECTION_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkConnectionInformationProtocolVersionID"></a>

### NetworkConnectionInformationProtocolVersionID
The Internet Protocol version identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_UNKNOWN | 0 |  |
| NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_4 | 4 |  |
| NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_INTERNET_PROTOCOL_VERSION_6 | 6 |  |
| NETWORK_CONNECTION_INFORMATION_PROTOCOL_VERSION_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkEndpointTypeID"></a>

### NetworkEndpointTypeID
The network endpoint type ID.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_ENDPOINT_TYPE_ID_UNKNOWN | 0 |  |
| NETWORK_ENDPOINT_TYPE_ID_SERVER | 1 |  |
| NETWORK_ENDPOINT_TYPE_ID_DESKTOP | 2 |  |
| NETWORK_ENDPOINT_TYPE_ID_LAPTOP | 3 |  |
| NETWORK_ENDPOINT_TYPE_ID_TABLET | 4 |  |
| NETWORK_ENDPOINT_TYPE_ID_MOBILE | 5 |  |
| NETWORK_ENDPOINT_TYPE_ID_VIRTUAL | 6 |  |
| NETWORK_ENDPOINT_TYPE_ID_IOT | 7 |  |
| NETWORK_ENDPOINT_TYPE_ID_BROWSER | 8 |  |
| NETWORK_ENDPOINT_TYPE_ID_FIREWALL | 9 |  |
| NETWORK_ENDPOINT_TYPE_ID_SWITCH | 10 |  |
| NETWORK_ENDPOINT_TYPE_ID_HUB | 11 |  |
| NETWORK_ENDPOINT_TYPE_ID_ROUTER | 12 |  |
| NETWORK_ENDPOINT_TYPE_ID_IDS | 13 |  |
| NETWORK_ENDPOINT_TYPE_ID_IPS | 14 |  |
| NETWORK_ENDPOINT_TYPE_ID_LOAD_BALANCER | 15 |  |
| NETWORK_ENDPOINT_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-NetworkInterfaceTypeID"></a>

### NetworkInterfaceTypeID
The network interface type identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| NETWORK_INTERFACE_TYPE_ID_UNKNOWN | 0 |  |
| NETWORK_INTERFACE_TYPE_ID_WIRED | 1 |  |
| NETWORK_INTERFACE_TYPE_ID_WIRELESS | 2 |  |
| NETWORK_INTERFACE_TYPE_ID_MOBILE | 3 |  |
| NETWORK_INTERFACE_TYPE_ID_TUNNEL | 4 |  |
| NETWORK_INTERFACE_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-ObservableTypeID"></a>

### ObservableTypeID
The observable value type identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| OBSERVABLE_TYPE_ID_UNKNOWN | 0 |  |
| OBSERVABLE_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-OperatingSystemOSTypeID"></a>

### OperatingSystemOSTypeID
The type identifier of the operating system.

| Name | Number | Description |
| ---- | ------ | ----------- |
| OPERATING_SYSTEM_OSTYPE_ID_UNKNOWN | 0 |  |
| OPERATING_SYSTEM_OSTYPE_ID_OTHER | 99 |  |
| OPERATING_SYSTEM_OSTYPE_ID_WINDOWS | 100 |  |
| OPERATING_SYSTEM_OSTYPE_ID_WINDOWS_MOBILE | 101 |  |
| OPERATING_SYSTEM_OSTYPE_ID_LINUX | 200 |  |
| OPERATING_SYSTEM_OSTYPE_ID_ANDROID | 201 |  |
| OPERATING_SYSTEM_OSTYPE_ID_MACOS | 300 |  |
| OPERATING_SYSTEM_OSTYPE_ID_IOS | 301 |  |
| OPERATING_SYSTEM_OSTYPE_ID_IPADOS | 302 |  |
| OPERATING_SYSTEM_OSTYPE_ID_SOLARIS | 400 |  |
| OPERATING_SYSTEM_OSTYPE_ID_AIX | 401 |  |
| OPERATING_SYSTEM_OSTYPE_ID_HP_UX | 402 |  |



<a name="ocsf-v1alpha-ProcessIntegrityLevel"></a>

### ProcessIntegrityLevel
The normalized identifier of the process integrity level (Windows only).

| Name | Number | Description |
| ---- | ------ | ----------- |
| PROCESS_INTEGRITY_LEVEL_UNKNOWN | 0 |  |
| PROCESS_INTEGRITY_LEVEL_UNTRUSTED | 1 |  |
| PROCESS_INTEGRITY_LEVEL_LOW | 2 |  |
| PROCESS_INTEGRITY_LEVEL_MEDIUM | 3 |  |
| PROCESS_INTEGRITY_LEVEL_HIGH | 4 |  |
| PROCESS_INTEGRITY_LEVEL_SYSTEM | 5 |  |
| PROCESS_INTEGRITY_LEVEL_PROTECTED | 6 |  |
| PROCESS_INTEGRITY_LEVEL_OTHER | 99 |  |



<a name="ocsf-v1alpha-ReputationReputationScoreID"></a>

### ReputationReputationScoreID
The normalized reputation score identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| REPUTATION_REPUTATION_SCORE_ID_UNKNOWN | 0 |  |
| REPUTATION_REPUTATION_SCORE_ID_VERY_SAFE | 1 |  |
| REPUTATION_REPUTATION_SCORE_ID_SAFE | 2 |  |
| REPUTATION_REPUTATION_SCORE_ID_PROBABLY_SAFE | 3 |  |
| REPUTATION_REPUTATION_SCORE_ID_LEANS_SAFE | 4 |  |
| REPUTATION_REPUTATION_SCORE_ID_MAY_NOT_BE_SAFE | 5 |  |
| REPUTATION_REPUTATION_SCORE_ID_EXERCISE_CAUTION | 6 |  |
| REPUTATION_REPUTATION_SCORE_ID_SUSPICIOUS_OR_RISKY | 7 |  |
| REPUTATION_REPUTATION_SCORE_ID_POSSIBLY_MALICIOUS | 8 |  |
| REPUTATION_REPUTATION_SCORE_ID_PROBABLY_MALICIOUS | 9 |  |
| REPUTATION_REPUTATION_SCORE_ID_MALICIOUS | 10 |  |
| REPUTATION_REPUTATION_SCORE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SCIMAuthProtocolID"></a>

### SCIMAuthProtocolID
The normalized identifier of the authorization protocol used by the SCIM
resource.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SCIMAUTH_PROTOCOL_ID_UNKNOWN | 0 |  |
| SCIMAUTH_PROTOCOL_ID_NTLM | 1 |  |
| SCIMAUTH_PROTOCOL_ID_KERBEROS | 2 |  |
| SCIMAUTH_PROTOCOL_ID_DIGEST | 3 |  |
| SCIMAUTH_PROTOCOL_ID_OPENID | 4 |  |
| SCIMAUTH_PROTOCOL_ID_SAML | 5 |  |
| SCIMAUTH_PROTOCOL_ID_OAUTH_2_0 | 6 |  |
| SCIMAUTH_PROTOCOL_ID_PAP | 7 |  |
| SCIMAUTH_PROTOCOL_ID_CHAP | 8 |  |
| SCIMAUTH_PROTOCOL_ID_EAP | 9 |  |
| SCIMAUTH_PROTOCOL_ID_RADIUS | 10 |  |
| SCIMAUTH_PROTOCOL_ID_BASIC_AUTHENTICATION | 11 |  |
| SCIMAUTH_PROTOCOL_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SCIMStateID"></a>

### SCIMStateID
The normalized state ID of the SCIM resource to reflect its activation
status.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SCIMSTATE_ID_UNKNOWN | 0 |  |
| SCIMSTATE_ID_PENDING | 1 |  |
| SCIMSTATE_ID_ACTIVE | 2 |  |
| SCIMSTATE_ID_FAILED | 3 |  |
| SCIMSTATE_ID_DELETED | 4 |  |
| SCIMSTATE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SSOAuthProtocolID"></a>

### SSOAuthProtocolID
The normalized identifier of the authentication protocol used by the SSO
resource.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SSOAUTH_PROTOCOL_ID_UNKNOWN | 0 |  |
| SSOAUTH_PROTOCOL_ID_NTLM | 1 |  |
| SSOAUTH_PROTOCOL_ID_KERBEROS | 2 |  |
| SSOAUTH_PROTOCOL_ID_DIGEST | 3 |  |
| SSOAUTH_PROTOCOL_ID_OPENID | 4 |  |
| SSOAUTH_PROTOCOL_ID_SAML | 5 |  |
| SSOAUTH_PROTOCOL_ID_OAUTH_2_0 | 6 |  |
| SSOAUTH_PROTOCOL_ID_PAP | 7 |  |
| SSOAUTH_PROTOCOL_ID_CHAP | 8 |  |
| SSOAUTH_PROTOCOL_ID_EAP | 9 |  |
| SSOAUTH_PROTOCOL_ID_RADIUS | 10 |  |
| SSOAUTH_PROTOCOL_ID_BASIC_AUTHENTICATION | 11 |  |
| SSOAUTH_PROTOCOL_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SecurityControlActionID"></a>

### SecurityControlActionID
The action taken by a control or other policy-based system leading to an
outcome or disposition. An unknown action may still correspond to a known
disposition. Refer to disposition_id for the outcome of the action.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SECURITY_CONTROL_ACTION_ID_UNKNOWN | 0 |  |
| SECURITY_CONTROL_ACTION_ID_ALLOWED | 1 |  |
| SECURITY_CONTROL_ACTION_ID_DENIED | 2 |  |
| SECURITY_CONTROL_ACTION_ID_OBSERVED | 3 |  |
| SECURITY_CONTROL_ACTION_ID_MODIFIED | 4 |  |
| SECURITY_CONTROL_ACTION_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SecurityControlConfidenceID"></a>

### SecurityControlConfidenceID
The normalized confidence refers to the accuracy of the rule that created the
finding. A rule with a low confidence means that the finding scope is wide
and may create finding reports that may not be malicious in nature.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SECURITY_CONTROL_CONFIDENCE_ID_UNKNOWN | 0 |  |
| SECURITY_CONTROL_CONFIDENCE_ID_LOW | 1 |  |
| SECURITY_CONTROL_CONFIDENCE_ID_MEDIUM | 2 |  |
| SECURITY_CONTROL_CONFIDENCE_ID_HIGH | 3 |  |
| SECURITY_CONTROL_CONFIDENCE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SecurityControlDispositionID"></a>

### SecurityControlDispositionID
Describes the outcome or action taken by a security control, such as access
control checks, malware detections or various types of policy violations.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SECURITY_CONTROL_DISPOSITION_ID_UNKNOWN | 0 |  |
| SECURITY_CONTROL_DISPOSITION_ID_ALLOWED | 1 |  |
| SECURITY_CONTROL_DISPOSITION_ID_BLOCKED | 2 |  |
| SECURITY_CONTROL_DISPOSITION_ID_QUARANTINED | 3 |  |
| SECURITY_CONTROL_DISPOSITION_ID_ISOLATED | 4 |  |
| SECURITY_CONTROL_DISPOSITION_ID_DELETED | 5 |  |
| SECURITY_CONTROL_DISPOSITION_ID_DROPPED | 6 |  |
| SECURITY_CONTROL_DISPOSITION_ID_CUSTOM_ACTION | 7 |  |
| SECURITY_CONTROL_DISPOSITION_ID_APPROVED | 8 |  |
| SECURITY_CONTROL_DISPOSITION_ID_RESTORED | 9 |  |
| SECURITY_CONTROL_DISPOSITION_ID_EXONERATED | 10 |  |
| SECURITY_CONTROL_DISPOSITION_ID_CORRECTED | 11 |  |
| SECURITY_CONTROL_DISPOSITION_ID_PARTIALLY_CORRECTED | 12 |  |
| SECURITY_CONTROL_DISPOSITION_ID_UNCORRECTED | 13 |  |
| SECURITY_CONTROL_DISPOSITION_ID_DELAYED | 14 |  |
| SECURITY_CONTROL_DISPOSITION_ID_DETECTED | 15 |  |
| SECURITY_CONTROL_DISPOSITION_ID_NO_ACTION | 16 |  |
| SECURITY_CONTROL_DISPOSITION_ID_LOGGED | 17 |  |
| SECURITY_CONTROL_DISPOSITION_ID_TAGGED | 18 |  |
| SECURITY_CONTROL_DISPOSITION_ID_ALERT | 19 |  |
| SECURITY_CONTROL_DISPOSITION_ID_COUNT | 20 |  |
| SECURITY_CONTROL_DISPOSITION_ID_RESET | 21 |  |
| SECURITY_CONTROL_DISPOSITION_ID_CAPTCHA | 22 |  |
| SECURITY_CONTROL_DISPOSITION_ID_CHALLENGE | 23 |  |
| SECURITY_CONTROL_DISPOSITION_ID_ACCESS_REVOKED | 24 |  |
| SECURITY_CONTROL_DISPOSITION_ID_REJECTED | 25 |  |
| SECURITY_CONTROL_DISPOSITION_ID_UNAUTHORIZED | 26 |  |
| SECURITY_CONTROL_DISPOSITION_ID_ERROR | 27 |  |
| SECURITY_CONTROL_DISPOSITION_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-SecurityControlRiskLevelID"></a>

### SecurityControlRiskLevelID
The normalized risk level id.

| Name | Number | Description |
| ---- | ------ | ----------- |
| SECURITY_CONTROL_RISK_LEVEL_ID_INFO | 0 |  |
| SECURITY_CONTROL_RISK_LEVEL_ID_LOW | 1 |  |
| SECURITY_CONTROL_RISK_LEVEL_ID_MEDIUM | 2 |  |
| SECURITY_CONTROL_RISK_LEVEL_ID_HIGH | 3 |  |
| SECURITY_CONTROL_RISK_LEVEL_ID_CRITICAL | 4 |  |
| SECURITY_CONTROL_RISK_LEVEL_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-TLSExtensionTypeID"></a>

### TLSExtensionTypeID
The TLS extension type identifier. See The Transport Layer Security (TLS)
extension page.

| Name | Number | Description |
| ---- | ------ | ----------- |
| TLSEXTENSION_TYPE_ID_SERVER_NAME | 0 |  |
| TLSEXTENSION_TYPE_ID_MAXIMUM_FRAGMENT_LENGTH | 1 |  |
| TLSEXTENSION_TYPE_ID_STATUS_REQUEST | 5 |  |
| TLSEXTENSION_TYPE_ID_SUPPORTED_GROUPS | 10 |  |
| TLSEXTENSION_TYPE_ID_SIGNATURE_ALGORITHMS | 13 |  |
| TLSEXTENSION_TYPE_ID_USE_SRTP | 14 |  |
| TLSEXTENSION_TYPE_ID_HEARTBEAT | 15 |  |
| TLSEXTENSION_TYPE_ID_APPLICATION_LAYER_PROTOCOL_NEGOTIATION | 16 |  |
| TLSEXTENSION_TYPE_ID_SIGNED_CERTIFICATE_TIMESTAMP | 18 |  |
| TLSEXTENSION_TYPE_ID_CLIENT_CERTIFICATE_TYPE | 19 |  |
| TLSEXTENSION_TYPE_ID_SERVER_CERTIFICATE_TYPE | 20 |  |
| TLSEXTENSION_TYPE_ID_PADDING | 21 |  |
| TLSEXTENSION_TYPE_ID_PRE_SHARED_KEY | 41 |  |
| TLSEXTENSION_TYPE_ID_EARLY_DATA | 42 |  |
| TLSEXTENSION_TYPE_ID_SUPPORTED_VERSIONS | 43 |  |
| TLSEXTENSION_TYPE_ID_COOKIE | 44 |  |
| TLSEXTENSION_TYPE_ID_PSK_KEY_EXCHANGE_MODES | 45 |  |
| TLSEXTENSION_TYPE_ID_CERTIFICATE_AUTHORITIES | 47 |  |
| TLSEXTENSION_TYPE_ID_OID_FILTERS | 48 |  |
| TLSEXTENSION_TYPE_ID_POST_HANDSHAKE_AUTH | 49 |  |
| TLSEXTENSION_TYPE_ID_SIGNATURE_ALGORITHMS_CERT | 50 |  |
| TLSEXTENSION_TYPE_ID_KEY_SHARE | 51 |  |
| TLSEXTENSION_TYPE_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-UniformResourceLocatorWebsiteCategorizationIDs"></a>

### UniformResourceLocatorWebsiteCategorizationIDs
The Website categorization identifiers.

| Name | Number | Description |
| ---- | ------ | ----------- |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_UNKNOWN | 0 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ADULT_OR_MATURE_CONTENT | 1 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PORNOGRAPHY | 3 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SEX_EDUCATION | 4 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_INTIMATE_APPAREL_OR_SWIMSUIT | 5 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_NUDITY | 6 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_EXTREME | 7 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SCAM_OR_QUESTIONABLE_OR_ILLEGAL | 9 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_GAMBLING | 11 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_VIOLENCE_OR_HATE_OR_RACISM | 14 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_WEAPONS | 15 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ABORTION | 16 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_HACKING | 17 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PHISHING | 18 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ENTERTAINMENT | 20 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_BUSINESS_OR_ECONOMY | 21 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ALTERNATIVE_SPIRITUALITY_OR_BELIEF | 22 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ALCOHOL | 23 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_TOBACCO | 24 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_CONTROLLED_SUBSTANCES | 25 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_CHILD_PORNOGRAPHY | 26 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_EDUCATION | 27 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_CHARITABLE_ORGANIZATIONS | 29 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ART_OR_CULTURE | 30 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_FINANCIAL_SERVICES | 31 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_BROKERAGE_OR_TRADING | 32 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_GAMES | 33 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_GOVERNMENT_OR_LEGAL | 34 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MILITARY | 35 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_POLITICAL_OR_SOCIAL_ADVOCACY | 36 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_HEALTH | 37 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_TECHNOLOGY_OR_INTERNET | 38 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SEARCH_ENGINES_OR_PORTALS | 40 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MALICIOUS_SOURCES_OR_MALNETS | 43 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MALICIOUS_OUTBOUND_DATA_OR_BOTNETS | 44 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_JOB_SEARCH_OR_CAREERS | 45 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_NEWS_OR_MEDIA | 46 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PERSONALS_OR_DATING | 47 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_REFERENCE | 49 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MIXED_CONTENT_OR_POTENTIALLY_ADULT | 50 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_CHAT_OR_SMS | 51 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_EMAIL | 52 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_NEWSGROUPS_OR_FORUMS | 53 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_RELIGION | 54 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SOCIAL_NETWORKING | 55 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_FILE_STORAGE_OR_SHARING | 56 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_REMOTE_ACCESS_TOOLS | 57 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SHOPPING | 58 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_AUCTIONS | 59 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_REAL_ESTATE | 60 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SOCIETY_OR_DAILY_LIVING | 61 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PERSONAL_SITES | 63 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_RESTAURANTS_OR_DINING_OR_FOOD | 64 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SPORTS_OR_RECREATION | 65 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_TRAVEL | 66 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_VEHICLES | 67 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_HUMOR_OR_JOKES | 68 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SOFTWARE_DOWNLOADS | 71 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PEER_TO_PEER | 83 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_AUDIO_OR_VIDEO_CLIPS | 84 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_OFFICE_OR_BUSINESS_APPLICATIONS | 85 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PROXY_AVOIDANCE | 86 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_FOR_KIDS | 87 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_WEB_ADS_OR_ANALYTICS | 88 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_WEB_HOSTING | 89 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_UNCATEGORIZED | 90 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SUSPICIOUS | 92 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SEXUAL_EXPRESSION | 93 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_TRANSLATION | 95 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_NON_VIEWABLE_OR_INFRASTRUCTURE | 96 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_CONTENT_SERVERS | 97 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PLACEHOLDERS | 98 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_OTHER | 99 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_SPAM | 101 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_POTENTIALLY_UNWANTED_SOFTWARE | 102 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_DYNAMIC_DNS_HOST | 103 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_E_CARD_OR_INVITATIONS | 106 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_INFORMATIONAL | 107 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_COMPUTER_OR_INFORMATION_SECURITY | 108 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_INTERNET_CONNECTED_DEVICES | 109 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_INTERNET_TELEPHONY | 110 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_ONLINE_MEETINGS | 111 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MEDIA_SHARING | 112 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_RADIO_OR_AUDIO_STREAMS | 113 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_TV_OR_VIDEO_STREAMS | 114 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_PIRACY_OR_COPYRIGHT_CONCERNS | 118 |  |
| UNIFORM_RESOURCE_LOCATOR_WEBSITE_CATEGORIZATION_IDS_MARIJUANA | 121 |  |



<a name="ocsf-v1alpha-UserRiskLevelID"></a>

### UserRiskLevelID
The normalized risk level id.

| Name | Number | Description |
| ---- | ------ | ----------- |
| USER_RISK_LEVEL_ID_INFO | 0 |  |
| USER_RISK_LEVEL_ID_LOW | 1 |  |
| USER_RISK_LEVEL_ID_MEDIUM | 2 |  |
| USER_RISK_LEVEL_ID_HIGH | 3 |  |
| USER_RISK_LEVEL_ID_CRITICAL | 4 |  |
| USER_RISK_LEVEL_ID_OTHER | 99 |  |



<a name="ocsf-v1alpha-UserTypeID"></a>

### UserTypeID
The account type identifier.

| Name | Number | Description |
| ---- | ------ | ----------- |
| USER_TYPE_ID_UNKNOWN | 0 |  |
| USER_TYPE_ID_USER | 1 |  |
| USER_TYPE_ID_ADMIN | 2 |  |
| USER_TYPE_ID_SYSTEM | 3 |  |
| USER_TYPE_ID_OTHER | 99 |  |


 

 

 



<a name="ocsf_v1alpha_cisco-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## ocsf/v1alpha/cisco.proto



<a name="ocsf-v1alpha-EndpointEvent"></a>

### EndpointEvent
The top-level definition for events associated with a single endpoint.


| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network_activity_detail | [NetworkActivity](#ocsf-v1alpha-NetworkActivity) |  | ocsf.ProcessActivity process_activity_detail = 101; ocsf.MemoryActivity memory_activity_detail = 102; ocsf.HTTPActivity http_activity_detail = 103; ocsf.FileSystemActivity file_activity_detail = 104; ocsf.DetectionFinding detection_finding_detail = 105; ocsf.RegistryKeyActivity registry_key_activity_detail = 106; ocsf.RegistryValueActivity registry_value_activity_detail = 107; ocsf.DNSActivity dns_activity_detail = 108; ocsf.WindowsServiceActivity windows_service_activity_detail = 109; ocsf.ScheduledJobActivity scheduled_job_activity_detail = 110; ocsf.ScriptActivity script_activity_detail = 111;

ocsf.Authentication authentication_detail = 113; ocsf.ProcessQuery process_query_detail = 114; |





 

 

 

 



<a name="ocsf_v1alpha_grpc-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## ocsf/v1alpha/grpc.proto



<a name="ocsf-v1alpha-StreamOCSFRequest"></a>

### StreamOCSFRequest







<a name="ocsf-v1alpha-StreamOCSFResponse"></a>

### StreamOCSFResponse



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| network_activity_detail | [NetworkActivity](#ocsf-v1alpha-NetworkActivity) |  | ocsf.ProcessActivity process_activity_detail = 101; ocsf.MemoryActivity memory_activity_detail = 102; ocsf.HTTPActivity http_activity_detail = 103; ocsf.FileSystemActivity file_activity_detail = 104; ocsf.DetectionFinding detection_finding_detail = 105; ocsf.RegistryKeyActivity registry_key_activity_detail = 106; ocsf.RegistryValueActivity registry_value_activity_detail = 107; ocsf.DNSActivity dns_activity_detail = 108; ocsf.WindowsServiceActivity windows_service_activity_detail = 109; ocsf.ScheduledJobActivity scheduled_job_activity_detail = 110; ocsf.ScriptActivity script_activity_detail = 111;

ocsf.Authentication authentication_detail = 113; ocsf.ProcessQuery process_query_detail = 114; |





 

 

 


<a name="ocsf-v1alpha-OCSFService"></a>

### OCSFService


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| StreamOCSF | [StreamOCSFRequest](#ocsf-v1alpha-StreamOCSFRequest) | [StreamOCSFResponse](#ocsf-v1alpha-StreamOCSFResponse) stream |  |

 



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

