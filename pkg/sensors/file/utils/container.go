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
	"fmt"
	"path"
	"strings"

	"github.com/containerd/containerd"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

// we only support containerd and docker engines for now
const (
	ContainerdPrefix = "containerd://"
	DockerPrefix     = "docker://"
)

// ths removes the prefix from a container ID (i.e. "containerd://")
func RemoveContainerIdPrefix(cId string) string {
	if strings.HasPrefix(cId, ContainerdPrefix) {
		return strings.TrimPrefix(cId, ContainerdPrefix)
	} else if strings.HasPrefix(cId, DockerPrefix) {
		return strings.TrimPrefix(cId, DockerPrefix)
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
func ContainerdIdToRootFs(cid string) (string, error) {
	addr := "/run/containerd/containerd.sock"
	ctx := context.Background()

	if root, err := getContainerdRoot(ctx, addr, "k8s.io", cid); err == nil {
		return root, nil
	}

	// this is only for e2e tests inside kind
	return getNestedContainerdRoot(ctx, addr, cid)
}

// returns the root directory of a container on docker runtime
// expect container ID without any prefix
func DockerIdToRootFs(cid string) (string, error) {
	ctx := context.Background()
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

// returns the root directory of a container
// it check the prefix of cid argument in order to determine
// the container runtime
func ContainerIdToRootFs(cid string) (string, error) {
	if strings.HasPrefix(cid, ContainerdPrefix) {
		c := strings.TrimPrefix(cid, ContainerdPrefix)
		rootDir, err := ContainerdIdToRootFs(c)
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
	} else {
		return "", fmt.Errorf("fim supports only containerd and docker engines [%s]", cid)
	}
}
