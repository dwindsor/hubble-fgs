package util

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"

	"github.com/docker/docker/api/types"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/isovalent/hubble-fgs/tests/compliance/config"
	"github.com/isovalent/hubble-fgs/tests/compliance/testcontext"
)

func ReadMessageStreamUntilError(reader io.Reader) ([]*jsonmessage.JSONMessage, error) {
	var msgs = []*jsonmessage.JSONMessage{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		msg := new(jsonmessage.JSONMessage)
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

func RunCommandInContainerWithEnvironment(ctx *testcontext.TestContext, env []string, cmd ...string) ([]string, error) {
	out := []string{}

	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return []string{}, fmt.Errorf("failed to create docker client: %w", err)
	}

	res, err := client.ContainerExecCreate(ctx.Ctx, ctx.ContainerId, types.ExecConfig{
		Tty:          true,
		AttachStderr: true,
		AttachStdout: true,
		Cmd:          cmd,
		Env:          env,
	})
	if err != nil {
		return out, fmt.Errorf("failed to create exec: %w", err)
	}
	execID := res.ID

	execRes, err := client.ContainerExecAttach(ctx.Ctx, execID, types.ExecStartCheck{
		Detach: false,
		Tty:    true,
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

	inspect, err := client.ContainerExecInspect(ctx.Ctx, execID)
	if err != nil {
		return out, fmt.Errorf("failed to inspect exec: %w", err)
	}

	if inspect.ExitCode != 0 {
		return out, fmt.Errorf("non-zero exit code: %d", inspect.ExitCode)
	}

	return out, nil
}

func RunCommandInContainer(ctx *testcontext.TestContext, cmd ...string) ([]string, error) {
	return RunCommandInContainerWithEnvironment(ctx, nil, cmd...)
}
