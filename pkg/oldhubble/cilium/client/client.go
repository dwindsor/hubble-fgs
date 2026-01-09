// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package client

import (
	"github.com/cilium/cilium/api/v1/models"
	clientPkg "github.com/cilium/cilium/pkg/client"
)

// Client is the interface for Cilium API.
type Client interface {
	GetIPCache() ([]*models.IPListEntry, error)
}

// Cilium is an abstraction to communicate with the cilium-agent.
type Cilium struct {
	*clientPkg.Client
}

// NewClient returns a new Cilium client that will connect to the cilium-agent.
func NewClient() (*Cilium, error) {
	ciliumClient, err := clientPkg.NewClient("")
	if err != nil {
		return nil, err
	}
	return &Cilium{
		Client: ciliumClient,
	}, nil
}

// GetIPCache retrieves the contents of the Cilium ipcache
func (c *Cilium) GetIPCache() ([]*models.IPListEntry, error) {
	ips, err := c.Policy.GetIP(nil)
	if err != nil {
		return nil, err
	}
	return ips.Payload, nil
}
