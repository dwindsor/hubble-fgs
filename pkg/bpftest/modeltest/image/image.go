// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package image

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/docker/docker/api/types/build"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/moby/go-archive"

	"github.com/isovalent/hubble-fgs/pkg/testutils"
)

const dockerAPIVersion = "1.45"

type ImageSource func(ctx context.Context) (string, error)

func Pull(tag string, useExisting bool) ImageSource {
	return func(ctx context.Context) (string, error) {
		FixDockerAPIVersion()

		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return tag, err
		}
		defer cli.Close()

		if useExisting && exists(ctx, cli, tag) {
			return tag, nil
		}

		res, err := cli.ImagePull(
			ctx,
			tag,
			image.PullOptions{},
		)
		if err != nil {
			return tag, fmt.Errorf("failed to pull image %q: %w", tag, err)
		}
		defer res.Close()

		_, err = io.Copy(os.Stdout, res)
		if err != nil {
			return tag, fmt.Errorf("failed read image pull response: %w", err)
		}

		return tag, nil
	}
}

func Build(dockerfile, tag string, useExisting bool) ImageSource {
	dockerfile = testutils.RepoRootPath(dockerfile)

	return func(ctx context.Context) (string, error) {
		FixDockerAPIVersion()

		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			return tag, err
		}
		defer cli.Close()

		if useExisting && exists(ctx, cli, tag) {
			return tag, nil
		}

		absDockerfile, err := filepath.Abs(dockerfile)
		if err != nil {
			return tag, fmt.Errorf("unable to convert %q into an absolute path", dockerfile)
		}

		buildCtxPath := path.Dir(absDockerfile)
		buildCtx, err := archive.TarWithOptions(buildCtxPath, &archive.TarOptions{})
		if err != nil {
			return tag, fmt.Errorf("failed to archive %q as build context for image %q: %w", buildCtxPath, tag, err)
		}

		res, err := cli.ImageBuild(
			ctx,
			buildCtx,
			build.ImageBuildOptions{
				Context:    buildCtx,
				Dockerfile: path.Base(dockerfile),
				Remove:     true,
				Tags:       []string{tag},
			},
		)
		if err != nil {
			return tag, fmt.Errorf("failed to build image %q for dockerfile %q: %w", tag, dockerfile, err)
		}
		defer res.Body.Close()

		_, err = io.Copy(os.Stdout, res.Body)
		if err != nil {
			return tag, fmt.Errorf("failed read image %q build response: %w", tag, err)
		}

		return tag, nil
	}
}

func exists(ctx context.Context, cli client.APIClient, tag string) bool {
	images, _ := cli.ImageList(ctx, image.ListOptions{
		Filters: filters.NewArgs(filters.Arg("reference", tag)),
	})
	return len(images) > 0
}

func FixDockerAPIVersion() {
	if os.Getenv("DOCKER_API_VERSION") == "" {
		os.Setenv("DOCKER_API_VERSION", dockerAPIVersion)
	}
}
