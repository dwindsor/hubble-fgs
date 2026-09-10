//go:build nok8s

package tetragon

import (
	"context"
	"errors"

	"github.com/cilium/tetragon/pkg/rthooks"
	"github.com/cilium/tetragon/pkg/watcher"

	"github.com/isovalent/hubble-fgs/pkg/alerts"
	model "github.com/isovalent/hubble-fgs/pkg/model/server"
	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

func initK8s(_ alerts.RuleManager) error {
	return nil
}

func initK8sMetrics() {
}

func k8sPodAccessor() watcher.PodAccessor {
	return nil
}

func getHooksRunner(_ watcher.PodAccessor) *rthooks.Runner {
	return nil
}

func startApplicationModelExporter(ctx context.Context, modelServer *model.Server) error {
	return errors.New("application model not supported in nok8s builds")
}

func initCilumState(_ context.Context) error {
	if enterpriseOption.Config.EnableCilium {
		return errors.New("cilium cannot be enabled in a nok8s build")
	}
	return nil
}
