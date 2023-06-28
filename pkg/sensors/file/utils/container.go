//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	crTypes "github.com/cri-o/cri-o/pkg/types"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// we support containerd, docker, and cri-o engines
const (
	ContainerdPrefix = "containerd://"
	DockerPrefix     = "docker://"
	CrioPrefix       = "cri-o://"
)

// ths removes the prefix from a container ID (i.e. "containerd://")
func RemoveContainerIdPrefix(cId string) string {
	if strings.HasPrefix(cId, ContainerdPrefix) {
		return strings.TrimPrefix(cId, ContainerdPrefix)
	} else if strings.HasPrefix(cId, DockerPrefix) {
		return strings.TrimPrefix(cId, DockerPrefix)
	} else if strings.HasPrefix(cId, CrioPrefix) {
		return strings.TrimPrefix(cId, CrioPrefix)
	}
	return cId
}

// lists all containerd namespaces for a specific client
func getContainedNamespaces(ctx context.Context, client *containerd.Client) ([]string, error) {
	namespaces := client.NamespaceService()
	return namespaces.List(ctx)
}

// searches for a container at a specific containerd namespace
// and returns the path to the root of this container
func getContainerdRoot(ctx context.Context, address, namespace, cid string) (string, error) {
	defaultNs := containerd.WithDefaultNamespace(namespace)
	client, err := containerd.New(address, defaultNs)
	if err != nil {
		return "", err
	}
	defer client.Close()

	containers, err := client.Containers(ctx)
	if err != nil {
		return "", err
	}

	for _, c := range containers {
		if c.ID() == cid {
			if tsk, err := c.Task(ctx, nil); err == nil {
				return fmt.Sprintf("/proc/%d/root/", tsk.Pid()), nil
			}
		}
	}
	return "", fmt.Errorf("cannot find container with ID %s", cid)
}

// similar to getContainerdRoot() but it search in a nested container setup (i.e. 2 levels)
// this is only needed for e2e tests in KinD
func getNestedContainerdRoot(ctx context.Context, address, cid string) (string, error) {
	client, err := containerd.New(address)
	if err != nil {
		return "", err
	}
	defer client.Close()

	nss, err := getContainedNamespaces(ctx, client)
	if err != nil {
		return "", err
	}

	for _, ns := range nss {
		clientNs, err := containerd.New(address, containerd.WithDefaultNamespace(ns))
		if err != nil {
			return "", err
		}
		defer clientNs.Close()

		containers, err := clientNs.Containers(ctx)
		if err != nil {
			return "", err
		}

		for _, c := range containers {
			if tsk, err := c.Task(ctx, nil); err == nil {
				root := fmt.Sprintf("/proc/%d/root/", tsk.Pid())
				if rt, err := getContainerdRoot(ctx, path.Join(root, address), "k8s.io", cid); err == nil {
					return path.Join(root, rt), nil
				}
			}
		}
	}
	return "", fmt.Errorf("cannot find container with ID %s", cid)
}

// returns the root directory of a container on containerd runtime
// expect container ID without any prefix
func ContainerdIdToRootFs(cid, endpoint string) (string, error) {
	addr := "/run/containerd/containerd.sock"
	if endpoint != "" {
		addr = endpoint
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	if root, err := getContainerdRoot(ctx, addr, "k8s.io", cid); err == nil {
		return root, nil
	}

	// this is only for e2e tests inside kind
	return getNestedContainerdRoot(ctx, addr, cid)
}

// returns the root directory of a container on docker runtime
// expect container ID without any prefix
func DockerIdToRootFs(cid string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	defer cli.Close()

	cnts, err := cli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return "", err
	}

	for _, c := range cnts {
		if c.ID == cid {
			if j, err := cli.ContainerInspect(ctx, c.ID); err == nil {
				return fmt.Sprintf("/proc/%d/root/", j.State.Pid), nil
			}
		}
	}
	return "", fmt.Errorf("cannot find container with ID %s", cid)
}

// Mainly inspired by https://github.com/cri-o/cri-o/blob/7d45aa0eb8460d72b441f17e4921b622513651cd/internal/client/client.go
// CrioClient is an interface to get information from crio daemon endpoint.
type CrioClient interface {
	ContainerInfo(string) (*crTypes.ContainerInfo, error)
}

type crioClientImpl struct {
	client         *http.Client
	crioSocketPath string
}

func configureUnixTransport(tr *http.Transport, proto, addr string) error {
	if len(addr) > len(syscall.RawSockaddrUnix{}.Path) {
		return fmt.Errorf("unix socket path %q is too long", addr)
	}
	// No need for compression in local communications.
	tr.DisableCompression = true
	tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.DialTimeout(proto, addr, 4*time.Second)
	}
	return nil
}

// New returns a crio client
func NewCrioClient(crioSocketPath string) (CrioClient, error) {
	tr := new(http.Transport)
	if err := configureUnixTransport(tr, "unix", crioSocketPath); err != nil {
		return nil, err
	}
	c := &http.Client{
		Transport: tr,
	}
	return &crioClientImpl{
		client:         c,
		crioSocketPath: crioSocketPath,
	}, nil
}

func (c *crioClientImpl) getRequest(path string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, path, http.NoBody)
	if err != nil {
		return nil, err
	}
	// For local communications over a unix socket, it doesn't matter what
	// the host is. We just need a valid and meaningful host name.
	req.Host = "crio"
	req.URL.Host = c.crioSocketPath
	req.URL.Scheme = "http"
	return req, nil
}

// ContainerInfo returns container info by querying
// the cri-o container endpoint.
func (c *crioClientImpl) ContainerInfo(id string) (*crTypes.ContainerInfo, error) {
	inspectContainersEndpoint := "/containers"
	req, err := c.getRequest(inspectContainersEndpoint + "/" + id)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	cInfo := crTypes.ContainerInfo{}
	if err := json.NewDecoder(resp.Body).Decode(&cInfo); err != nil {
		return nil, err
	}
	return &cInfo, nil
}

// returns the root directory of a container on docker runtime
// expect container ID without any prefix
func CrioIdToRootFs(cid, endpoint string) (string, error) {
	defaultSocket := "/var/run/crio/crio.sock"
	if endpoint != "" {
		defaultSocket = endpoint
	}
	client, err := NewCrioClient(defaultSocket)
	if err != nil {
		return "", err
	}
	if cnt, err := client.ContainerInfo(cid); err == nil {
		return fmt.Sprintf("/proc/%d/root/", cnt.Pid), nil
	}
	return "", fmt.Errorf("cannot find container with ID %s", cid)
}

// returns the root directory of a container
// it check the prefix of cid argument in order to determine
// the container runtime
func ContainerIdToRootFs(cid, endpoint string) (string, error) {
	if strings.HasPrefix(cid, ContainerdPrefix) {
		c := strings.TrimPrefix(cid, ContainerdPrefix)
		rootDir, err := ContainerdIdToRootFs(c, endpoint)
		if err != nil {
			return "", err
		}
		return rootDir, nil
	} else if strings.HasPrefix(cid, DockerPrefix) {
		c := strings.TrimPrefix(cid, DockerPrefix)
		rootDir, err := DockerIdToRootFs(c)
		if err != nil {
			return "", err
		}
		return rootDir, nil
	} else if strings.HasPrefix(cid, CrioPrefix) {
		c := strings.TrimPrefix(cid, CrioPrefix)
		rootDir, err := CrioIdToRootFs(c, endpoint)
		if err != nil {
			return "", err
		}
		return rootDir, nil
	} else {
		return "", fmt.Errorf("fim supports only containerd and docker engines [%s]", cid)
	}
}
