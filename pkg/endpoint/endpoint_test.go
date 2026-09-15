// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package endpoint

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddEndpointRefreshesResourceIdentity(t *testing.T) {
	forward, err := lru.New[uint64, Endpoint](2)
	require.NoError(t, err)
	reverse, err := lru.New[endpointIdentity, uint64](2)
	require.NoError(t, err)
	cache := &Cache{cache: forward, revCache: reverse}

	service := Endpoint{
		Type:      tetragon.EndpointType_ENDPOINT_TYPE_SERVICE,
		Namespace: "default",
		Name:      "api",
		UID:       "1",
	}
	firstID, err := cache.AddEndpoint(service)
	require.NoError(t, err)

	service.UID = "2"
	secondID, err := cache.AddEndpoint(service)
	require.NoError(t, err)

	assert.Equal(t, firstID, secondID, "resource version updates should reuse the endpoint ID")
	stored, ok := cache.LookupID(firstID)
	require.True(t, ok, "updated endpoint should remain in the forward cache")
	assert.Equal(t, "2", stored.UID, "forward cache should contain the latest resource version")
}
