// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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
	ips, err := c.Client.Policy.GetIP(nil)
	if err != nil {
		return nil, err
	}
	return ips.Payload, nil
}
