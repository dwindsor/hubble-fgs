// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package util

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	docker "github.com/moby/moby/client"

	"github.com/isovalent/hubble-fgs/tests/compliance/config"
	"github.com/isovalent/hubble-fgs/tests/compliance/testcontext"
)

func ReadMessageStreamUntilError(reader io.Reader) ([]*jsonstream.Message, error) {
	var msgs = []*jsonstream.Message{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		msg := new(jsonstream.Message)
		bytes := scanner.Bytes()
		if err := json.Unmarshal(bytes, msg); err != nil {
			return msgs, fmt.Errorf("failed to deserialize message `%s`: %w", bytes, err)
		}
		msgs = append(msgs, msg)
		if msg.Error != nil {
			return msgs, fmt.Errorf("error from daemon: %w", msg.Error)
		}
	}
	if err := scanner.Err(); err != nil {
		return msgs, fmt.Errorf("error reading build output")
	}

	return msgs, nil
}

func WaitForContainer(ctx *testcontext.TestContext) (*container.WaitResponse, error) {
	client, err := docker.New(docker.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	waitRes := client.ContainerWait(ctx.Ctx, ctx.ContainerId, docker.ContainerWaitOptions{
		Condition: container.WaitConditionNotRunning,
	})
	select {
	case res := <-waitRes.Result:
		return &res, nil
	case err := <-waitRes.Error:
		return nil, fmt.Errorf("failed to wait for container: %w", err)
	}
}

func RunCommandInContainerWithEnvironment(ctx *testcontext.TestContext, env []string, cmd ...string) ([]string, error) {
	out := []string{}

	client, err := docker.New(docker.FromEnv)
	if err != nil {
		return []string{}, fmt.Errorf("failed to create docker client: %w", err)
	}

	res, err := client.ExecCreate(ctx.Ctx, ctx.ContainerId, docker.ExecCreateOptions{
		TTY:          true,
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmd,
		Env:          env,
	})
	if err != nil {
		return out, fmt.Errorf("failed to create exec: %w", err)
	}
	execID := res.ID

	execRes, err := client.ExecAttach(ctx.Ctx, execID, docker.ExecAttachOptions{
		TTY: true,
	})
	if err != nil {
		return out, fmt.Errorf("failed to exec: %w", err)
	}
	defer execRes.Close()

	scanner := bufio.NewScanner(execRes.Reader)
	for scanner.Scan() {
		line := scanner.Text()
		if config.Config().PrintContainerStdout {
			fmt.Println(line)
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("error reading output: %w", err)
	}

	return out, nil
}

func RunCommandInContainer(ctx *testcontext.TestContext, cmd ...string) ([]string, error) {
	return RunCommandInContainerWithEnvironment(ctx, nil, cmd...)
}
