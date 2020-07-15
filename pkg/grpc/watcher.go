package grpc

import (
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// K8sResourceWatcher defines an interface for accessing various resources from Kubernetes API.
type K8sResourceWatcher interface {
	// Find a pod/container pair for the given container ID.
	FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool)
}

// K8sWatcher maintains a local cache of k8s resources.
type K8sWatcher struct {
	podInformer cache.SharedIndexInformer
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient *kubernetes.Clientset, stateSyncIntervalSec time.Duration) *K8sWatcher {
	k8sInformerFactory := informers.NewSharedInformerFactoryWithOptions(k8sClient, stateSyncIntervalSec,
		informers.WithTweakListOptions(func(options *v1.ListOptions) {
			// Watch local pods only.
			options.FieldSelector = "spec.nodeName=" + os.Getenv("NODE_NAME")
		}))
	podInformer := k8sInformerFactory.Core().V1().Pods().Informer()
	k8sInformerFactory.Start(wait.NeverStop)
	k8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	return &K8sWatcher{podInformer: podInformer}
}

// FindPod implements K8sResourceWatcher.FindPod.
func (watcher *K8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return findPod(containerID, watcher.podInformer.GetStore().List())
}

// FakeK8sWatcher is used as an "empty" K8sResourceWatcher when --enable-k8s-api flag is not set.
type FakeK8sWatcher struct {
	pods []interface{}
}

// NewK8sWatcher returns a pointer to an initialized FakeK8sWatcher struct.
func NewFakeK8sWatcher(pods []interface{}) *FakeK8sWatcher {
	return &FakeK8sWatcher{pods: pods}
}

// FindPod implements K8sResourceWatcher.FindPod.
func (watcher *FakeK8sWatcher) FindPod(containerID string) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	return findPod(containerID, watcher.pods)
}

// TODO(michi) Not the most efficient implementation. Optimize as needed.
func findPod(containerID string, pods []interface{}) (*corev1.Pod, *corev1.ContainerStatus, bool) {
	if containerID == "" {
		return nil, nil, false
	}
	for _, obj := range pods {
		pod, ok := obj.(*corev1.Pod)
		if !ok {
			return nil, nil, false
		}
		for _, container := range pod.Status.ContainerStatuses {
			parts := strings.Split(container.ContainerID, "//")
			if len(parts) == 2 && strings.HasPrefix(parts[1], containerID) {
				return pod, &container, true
			}
		}
	}
	return nil, nil, false
}
