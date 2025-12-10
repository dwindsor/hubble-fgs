// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package local

import (
	"context"
	"net"
	"os"
)

// GenericMetadataService implements MetadataService for non-cloud environments
// (e.g., vSphere, bare-metal). It retrieves metadata from the local OS.
type GenericMetadataService struct {
	hostname string
}

func NewGenericMetadataService() (*GenericMetadataService, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	return &GenericMetadataService{hostname: hostname}, nil
}

func (m *GenericMetadataService) GetHostname(_ context.Context) (string, error) {
	return m.hostname, nil
}

func (m *GenericMetadataService) GetInstanceId(_ context.Context) (string, error) {
	// Use hostname as the instance ID for non-cloud environments
	return m.hostname, nil
}

func (m *GenericMetadataService) GetInternalIP(_ context.Context) (string, error) {
	return getFirstNonLoopbackIP()
}

func (m *GenericMetadataService) GetExternalIP(_ context.Context) (string, error) {
	// External IP is typically not available in non-cloud environments
	return "", nil
}

func (m *GenericMetadataService) GetInternalDNS(_ context.Context) (string, error) {
	return m.hostname, nil
}

func (m *GenericMetadataService) GetExternalDNS(_ context.Context) (string, error) {
	return "", nil
}

func (m *GenericMetadataService) GetLabels(_ context.Context) (map[string]string, error) {
	// Return basic labels for non-cloud environments
	labels := map[string]string{
		"tetragon.io/environment": "generic",
	}
	return labels, nil
}

// getFirstNonLoopbackIP returns the first non-loopback IPv4 address found on the system.
func getFirstNonLoopbackIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", nil
}
