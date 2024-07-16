package compliance

// NB(willfindlay): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/testutils"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/isovalent/hubble-fgs/tests/compliance/config"
	"github.com/isovalent/hubble-fgs/tests/compliance/testcontext"
	"github.com/isovalent/hubble-fgs/tests/compliance/util"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"sigs.k8s.io/yaml"

	// Needed to initialize custom sensor handlers
	_ "github.com/isovalent/hubble-fgs/pkg/sensors"
)

type Test struct {
	// Name of the compliance test. Should match the directory name in tests/compliance/tests.
	Name string
	// Tracing policy that should be loaded when performing the test.
	TracingPolicy *tracingpolicy.GenericTracingPolicy
	// Steps to run the test.
	Steps []Stepper
}

// Build and run the compliance test.
func (ct *Test) BuildAndRun(t *testing.T) error {
	ctx := context.Background()

	// Build the compliance test using its Dockerfile.
	if err := ct.Build(t, ctx); err != nil {
		return err
	}

	// Run the compliance test.
	return ct.Run(t, ctx)
}

// Run the compliance test.
//
// Invokes `docker create` and `docker run` with the appropriate arguments to create the
// container and run tests.
func (ct *Test) Run(t *testing.T, ctx context.Context) error {
	testCtx, err := ct.createTestContainer(t, ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := ct.stopTestContainer(testCtx); err != nil {
			t.Logf("error cleaning up test container: %s", err)
		}
	}()

	doneWG, err := ct.maybeListenForEvents(t, testCtx)
	if err != nil {
		return err
	}
	defer doneWG.Wait()

	err = ct.startTestContainer(t, testCtx)
	if err != nil {
		return err
	}

	for _, step := range ct.Steps {
		assert.NoError(t, step.Step(testCtx))
	}

	doneWG.Done()
	return nil
}

func (ct *Test) maybeListenForEvents(t *testing.T, ctx *testcontext.TestContext) (*sync.WaitGroup, error) {
	var readyWG, doneWG sync.WaitGroup

	if ct.TracingPolicy == nil || !config.Config().EnableTetragon {
		t.Log("Tetragon is disabled for this test")
		doneWG.Add(1)
		return &doneWG, nil
	}

	configFilePath := ct.ConfigFilePath()
	policyBytes, err := yaml.Marshal(ct.TracingPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TracingPolicy: %w", err)
	}
	err = observertesthelper.WriteConfigFile(configFilePath, string(policyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	if err := bpf.CheckOrMountCgroup2(); err != nil {
		return nil, fmt.Errorf("failed to check or mount cgroup2")
	}

	obs, err := enterpriseoth.GetDefaultObserverWithFile(t, ctx.Ctx, configFilePath, runner.Conf().TetragonLib)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for events: %w", err)
	}

	observertesthelper.LoopEvents(ctx.Ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	return &doneWG, nil
}

func (ct *Test) createTestContainer(t *testing.T, ctx context.Context, cmd ...string) (*testcontext.TestContext, error) {
	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}
	client.NegotiateAPIVersion(ctx)

	containerCfg := &container.Config{
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Image:        ct.Tag(),
		Cmd:          cmd,
	}

	res, err := client.ContainerCreate(ctx, containerCfg, &container.HostConfig{}, &network.NetworkingConfig{}, &v1.Platform{}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create test container: %w", err)
	}

	testCtx := &testcontext.TestContext{
		T:           t,
		Name:        ct.Name,
		ContainerId: res.ID,
		Ctx:         ctx,
	}

	t.Logf("test container created with id %s", res.ID)
	return testCtx, nil
}

func (ct *Test) startTestContainer(t *testing.T, ctx *testcontext.TestContext) error {
	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	client.NegotiateAPIVersion(ctx.Ctx)

	err = client.ContainerStart(ctx.Ctx, ctx.ContainerId, container.StartOptions{})
	if err != nil {
		return fmt.Errorf("failed to start test container: %w", err)
	}

	logReader, err := client.ContainerLogs(ctx.Ctx, ctx.ContainerId, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Since:      "",
		Until:      "",
		Timestamps: false,
		Follow:     true,
		Tail:       "",
		Details:    false,
	})
	if err != nil {
		return fmt.Errorf("failed to tail container logs: %w", err)
	}
	go func() {
		defer logReader.Close()
		scanner := bufio.NewScanner(logReader)
		for scanner.Scan() {
			line := scanner.Text()
			if config.Config().PrintContainerStdout {
				fmt.Println(line)
			}
			ctx.ContainerLogs = append(ctx.ContainerLogs, line)
		}
	}()

	t.Logf("test container started with id %s", ctx.ContainerId)
	return nil
}

func (ct *Test) stopTestContainer(ctx *testcontext.TestContext) error {
	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	client.NegotiateAPIVersion(ctx.Ctx)

	if err := client.ContainerStop(ctx.Ctx, ctx.ContainerId, container.StopOptions{}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	if config.Config().RemoveContainer {
		if err := client.ContainerRemove(ctx.Ctx, ctx.ContainerId, container.RemoveOptions{
			RemoveVolumes: true,
			RemoveLinks:   false,
			Force:         true,
		}); err != nil {
			return fmt.Errorf("failed to remove container: %w", err)
		}
	} else {
		ctx.T.Logf("refusing to clean up container %s due to -remove-container=false", ctx.ContainerId)
	}

	return nil
}

// Get the Docker tag associated with this compliance test.
func (ct *Test) Tag() string {
	return fmt.Sprintf("%s-compliance-test:latest", ct.Name)
}

// Get the path to the compliance test (where its Dockerfile resides).
//
// Path is computed using the Test's name.
func (ct *Test) Path() string {
	return testutils.RepoRootPath(path.Join("tests/compliance/tests", ct.Name))
}

// Path where we should write the Tetragon config file for the compliance test.
//
// Path is computed using the Test's name.
func (ct *Test) ConfigFilePath() string {
	return path.Join(os.TempDir(), fmt.Sprintf("%s-config.yaml", ct.Name))
}

// Build the compliance test.
//
// Invokes `docker build` with the appropriate arguments to build the compliance test.
func (ct *Test) Build(t *testing.T, ctx context.Context) error {
	t.Logf("building test %s...", ct.Tag())
	if _, err := os.Stat(path.Join(ct.Path(), "Dockerfile")); err != nil {
		return fmt.Errorf("unable to find Dockerfile for test: %w", err)
	}

	tar, err := archive.TarWithOptions(ct.Path(), &archive.TarOptions{})
	if err != nil {
		return fmt.Errorf("failed to open build context as tar archive")
	}

	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	client.NegotiateAPIVersion(ctx)

	res, err := client.ImageBuild(ctx, tar, types.ImageBuildOptions{
		Tags:       []string{ct.Tag()},
		Dockerfile: "Dockerfile",
		Remove:     true,
	})
	if err != nil {
		return fmt.Errorf("failed to build image: %w", err)
	}
	defer res.Body.Close()

	_, err = util.ReadMessageStreamUntilError(res.Body)
	if err != nil {
		return err
	}

	t.Logf("done building test %s", ct.Tag())
	return nil
}
