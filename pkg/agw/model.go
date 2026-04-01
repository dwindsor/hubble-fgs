// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package agw

// ------------- Log Configuration -------------

const (
	LogTypeSyslog    = "syslog"
	LogTypeIpfix     = "ipfix"
	LogTypeTimescape = "timescape"
	LogTypeSplunk    = "splunk"
)

type LogList map[string]LogConfigData

type LogConfigData struct {
	Id          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Type        string               `json:"type"`
	Config      LogConfigDataConfig  `json:"config"`
	Secrets     LogConfigDataSecrets `json:"secrets"`
}

type LogConfigDataConfig struct {
	Host  string `json:"host"`
	Port  string `json:"port"`
	Proto string `json:"protocol"` // "tcp" or "udp"
	Tls   bool   `json:"tls"`
}

type LogConfigDataSecrets struct {
	Token                 string `json:"token"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	MTLSIssuerGroup       string `json:"mtlsIssuerGroup"`
	MTLSIssuerKind        string `json:"mtlsIssuerKind"`
	MTLSIssuerName        string `json:"mtlsIssuerName"`
	MTLSCASecretName      string `json:"mtlsCASecretName"`
	MTLSCASecretNamespace string `json:"mtlsCASecretNamespace"`
}
