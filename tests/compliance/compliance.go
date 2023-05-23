package compliance

// NB(willfindlay): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument

import (
	"context"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
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
	testCtx, err := ct.startTestContainer(t, ctx)
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
	err = observer.WriteConfigFile(configFilePath, string(policyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}

	if err := bpf.CheckOrMountCgroup2(); err != nil {
		return nil, fmt.Errorf("failed to check or mount cgroup2")
	}

	obs, err := observer.GetDefaultObserverWithFile(t, ctx.Ctx, configFilePath, runner.Conf().TetragonLib)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for events: %w", err)
	}

	observer.LoopEvents(ctx.Ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	return &doneWG, nil
}

func (ct *Test) startTestContainer(t *testing.T, ctx context.Context) (*testcontext.TestContext, error) {
	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	res, err := client.ContainerCreate(ctx, &container.Config{
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Image:        ct.Tag(),
	}, &container.HostConfig{}, &network.NetworkingConfig{}, &v1.Platform{}, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create test container: %w", err)
	}

	err = client.ContainerStart(ctx, res.ID, types.ContainerStartOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to start test container: %w", err)
	}

	t.Logf("test container started with id %s", res.ID)
	return &testcontext.TestContext{T: t, ContainerId: res.ID, Name: ct.Name, Ctx: ctx}, nil
}

func (ct *Test) stopTestContainer(ctx *testcontext.TestContext) error {
	client, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}

	if err := client.ContainerStop(ctx.Ctx, ctx.ContainerId, container.StopOptions{}); err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	if err := client.ContainerRemove(ctx.Ctx, ctx.ContainerId, types.ContainerRemoveOptions{
		RemoveVolumes: true,
		RemoveLinks:   false,
		Force:         true,
	}); err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
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
