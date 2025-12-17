// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package token provides interfaces and implementations for managing authentication tokens,
// such as Kubernetes service account tokens or JWTs. The main responsibility of this package
// is to manage, validate, persist, and load authentication tokens required for secure
// communication with external systems like on-prem Kubernetes clusters.
//
// IAgentToken defines the contract for handling authentication tokens, including methods
// for retrieving, setting, validating, persisting, deleting, and loading token data.
package token

type IAgentToken interface {
	K8sAuthToken() string
	SetK8sAuthToken(token string)
	K8sAuthPath() string
	SetK8sAuthPath(path string)
	ValidK8sAuth() error
	Persist() error
	Delete() error
	Load() (bool, error)
}
