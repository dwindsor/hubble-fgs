package daemon

import (
	"context"

	"github.com/go-logr/logr"
	appv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/isovalent/hubble-fgs/operator/options"
)

// Reconciler reconciles Tetragon DaemonSet object
type Reconciler struct {
	client.Client
	Log logr.Logger
	//Scheme *runtime.Scheme
}

// Reconcile gets notified and reconciles the corresponding Tetragon DaemonSet object.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if (req.Namespace != options.Config.DaemonSetNamespace) || (req.Name != dsName) {
		// skip reconcile request if it's not Tetragon related
		return ctrl.Result{}, nil
	}

	l := r.Log.WithValues("name-namespace", req.NamespacedName)

	ds := &appv1.DaemonSet{}
	if err := r.Get(ctx, req.NamespacedName, ds); err != nil {
		if !k8serrors.IsNotFound(err) {
			l.Error(err, "unable to fetch daemon set")
			return ctrl.Result{}, err
		}
		l.Info("daemon set not found, creating")
		if err := r.Create(ctx, daemonSet()); err != nil {
			l.Error(err, "unable to create daemon set")
			return ctrl.Result{}, err
		}
		l.Info("daemon set created")
		return ctrl.Result{}, nil
	}

	dsTemplate := daemonSet()
	if !equality.Semantic.DeepEqual(ds.Labels, dsTemplate.Labels) ||
		!equality.Semantic.DeepEqual(ds.Spec, dsTemplate.Spec) {
		l.Info("updating daemon set")
		if err := r.Update(ctx, dsTemplate); err != nil {
			l.Error(err, "unable to update daemon set")
			return ctrl.Result{}, err
		}
		l.Info("daemon set updated")
	}
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&appv1.DaemonSet{}).
		Complete(r)
}
