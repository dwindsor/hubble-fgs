// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package image

import (
	"testing"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const alpineTag = "alpine:3.22.0"
const testificateTag = "testificate:latest"

func TestPullImage(t *testing.T) {
	tag, err := Pull(alpineTag, true)(t.Context())

	assert.NoError(t, err, "image pull should succeed")
	assert.Equal(t, alpineTag, tag, "tag should match")
}

func TestImageExists(t *testing.T) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	require.NoError(t, err, "docker client must create")
	defer cli.Close()

	assert.False(t, exists(t.Context(), cli, "some-made-up-tag"), "made up tag should not exist")

	_, err = Pull(alpineTag, false)(t.Context())
	require.NoError(t, err, "image must pull or exist")
	assert.True(t, exists(t.Context(), cli, alpineTag), "ubuntu tag should exist")
}

func TestBuildImage(t *testing.T) {
	tag, err := Build("pkg/bpftest/modeltest/testdata/Dockerfile.buildtest", testificateTag, false)(t.Context())

	assert.NoError(t, err, "image should build")
	assert.Equal(t, testificateTag, tag, "tag should match")
}
