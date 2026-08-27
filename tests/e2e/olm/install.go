// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package olm

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/install/tetragon"
	"github.com/cilium/tetragon/tests/e2e/state"

	"github.com/isovalent/hubble-fgs/operator/agent"

	"sigs.k8s.io/yaml"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	operatorsv1alpha1 "github.com/operator-framework/api/pkg/operators/v1alpha1"

	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"

	clientset "k8s.io/client-go/kubernetes"
)

const (
	olmNamespace = "olm"
	olmBaseURL   = "https://github.com/operator-framework/operator-lifecycle-manager/releases/download"
	// TODO: get it checked through renovate
	olmVersion = "v0.27.0"
)

var olmCRDsURL = olmBaseURL + "/" + olmVersion + "/crds.yaml"
var olmResourcesURL = olmBaseURL + "/" + olmVersion + "/olm.yaml"

//go:embed operatorgroup.yaml
var OperatorGroup string

//go:embed catalogsource.yaml
var CatalogSource string

//go:embed subscription.yaml
var Subscription string

// TetragonInstall deploys OLM and leverages it for the installation of Tetragon
func TetragonInstall(opts ...tetragon.Option) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		// TODO: This could also be added to runner as a "WithOLM" method
		o := processOpts(opts...)
		klog.InfoS("Installing OLM...")
		crdResponse, err := http.Get(olmCRDsURL)
		if err != nil {
			return ctx, err
		}
		defer crdResponse.Body.Close()
		olmCRDs, err := decoder.DecodeAll(ctx, crdResponse.Body)
		if err != nil {
			return ctx, err
		}
		if ctx, err = helpers.LoadObjects(olmNamespace, olmCRDs, true)(ctx, cfg); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctx, err
			}
		}
		objResponse, err := http.Get(olmResourcesURL)
		if err != nil {
			return ctx, err
		}
		defer objResponse.Body.Close()
		olmObjects, err := decoder.DecodeAll(ctx, objResponse.Body)
		if err != nil {
			return ctx, err
		}
		// helpers.LoadObjects enforces the namespace, which is not acceptable here.
		// TODO: make it configurable in helpers.LoadObjects, e.g. don't call
		// obj.SetNamespace(namespace) if the namespace is an empty string.
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(olmNamespace)
		if err := operatorsv1alpha1.AddToScheme(r.GetScheme()); err != nil {
			panic(err)
		}
		var olmCSV k8s.Object
		for _, obj := range olmObjects {
			// don't install operatorhub.io catalog
			if obj.GetObjectKind().GroupVersionKind().Kind == operatorsv1alpha1.CatalogSourceKind {
				continue
			}
			if obj.GetObjectKind().GroupVersionKind().Kind == operatorsv1alpha1.ClusterServiceVersionKind {
				olmCSV = obj
			}
			if err := r.Create(ctx, obj); err != nil {
				if !apierrors.IsAlreadyExists(err) {
					return ctx, err
				}
			}
			klog.V(2).InfoS("Created resource", "namespace", obj.GetNamespace(), "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		}
		if err := wait.For(conditions.New(r).ResourceMatch(olmCSV, func(object k8s.Object) bool {
			unstrCSV := object.(*unstructured.Unstructured)
			status, _, _ := unstructured.NestedString(unstrCSV.Object, "status", "phase")
			return status == string(operatorsv1alpha1.CSVPhaseSucceeded)
		})); err != nil {
			return ctx, err
		}

		klog.InfoS("Installing Tetragon...", "opts", o)
		opCM := agent.DefaultOperatorConfigMap(klog.NewKlogr(), o.Namespace, agent.OperatorConfigMapName)
		agentCMMap := agent.ValuesAsMap(klog.Background(), opCM.Data[agent.OperatorConfigMapAgentConfigMapKey])
		daemonsetMap := make(map[string]any)
		if err := yaml.Unmarshal([]byte(opCM.Data[agent.OperatorConfigMapAgentDaemonSetKey]), &daemonsetMap); err != nil {
			klog.V(2).ErrorS(err, "could not unmarshal the DaemonSet configuration", "value", opCM.Data[agent.OperatorConfigMapAgentDaemonSetKey])
			return nil, err
		}
		extraArgs := "\n    procfs: /procRootReal"
		if clusterName := helpers.GetTempKindClusterName(ctx); clusterName != "" {
			for _, key := range []string{tetragon.OperatorImageKey, tetragon.AgentImageKey} {
				if v := o.HelmValues[key]; v != "" {
					klog.InfoS("Loading image into kind cluster", "cluster", clusterName, "image", v, "helm", key)
					var err error
					if ctx, err = envfuncs.LoadDockerImageToCluster(clusterName, v)(ctx, cfg); err != nil {
						// If the image is not present locally, don't worry about it but log a message
						if strings.Contains(err.Error(), "not present locally") {
							klog.InfoS("Image is not present locally, attempting to install Tetragon regardless", "cluster", clusterName, "image", v, "helm", key)
						}
						return ctx, fmt.Errorf("failed to load image %s into cluster %s: %w", v, clusterName, err)
					}
				}
			}
		}
		// All helm values are not covered. This needs to be extended as required
		if v, ok := o.HelmValues["tetragon.exportAllowList"]; ok {
			agentCMMap["export-allowlist"] = v
		}
		if v, ok := o.HelmValues["tetragon.enablePolicyFilter"]; ok {
			agentCMMap["enable-policy-filter"] = v
		}
		if v, ok := o.HelmValues["tetragon.enableCiliumAPI"]; ok {
			agentCMMap["enable-cilium-api"] = v
		}
		if v, ok := o.HelmValues["tetragon.enableSandboxpolicies"]; ok {
			agentCMMap["enable-sandboxpolicies"] = v
		}
		if v, ok := o.HelmValues["tetragon.extraArgs.fim-fifo-path"]; ok {
			extraArgs += "\n    fim-fifo-path: " + v
		}
		// Handle BTF option for KinD cluster
		if o.BTF != "" {
			if clusterName := helpers.GetTempKindClusterName(ctx); clusterName != "" {
				controlPlaneId := fmt.Sprintf("%s-control-plane", clusterName)
				// TODO: podman users often define an alias or a shell function for docker
				// For this command to run in their environment it would require to be executed from a shell
				// something like exec.Command("bash", "-c", "docker cp...")
				cmd := exec.CommandContext(ctx, "docker", "cp", o.BTF, fmt.Sprintf("%s:/btf", controlPlaneId))
				err := cmd.Run()
				if err != nil {
					return ctx, fmt.Errorf("failed to load BTF file into KinD cluster: %w", err)
				}
				agentCMMap["btf"] = "/btf"
				extraHostPathMounts := []corev1.VolumeMount{
					{
						Name:      "btf",
						MountPath: "/btf",
					},
				}
				extraHostPathMountsBytes, err := yaml.Marshal(extraHostPathMounts)
				if err != nil {
					return ctx, fmt.Errorf("failed to marshal BTF volume: %w", err)
				}
				daemonsetMap["extraHostPathMounts"] = string(extraHostPathMountsBytes)
			} else {
				return ctx, fmt.Errorf("option -tetragon.btf only makes sense for KinD clusters")
			}
		}
		// Handle procRoot for KinD cluster
		if clusterName := helpers.GetTempKindClusterName(ctx); clusterName != "" {
			// real-host-proc lets us mount procFS from the real host rather than the KinD node
			hostPathDirectoryType := corev1.HostPathDirectory
			extraKindVolumes := []corev1.Volume{
				{
					Name: "real-host-proc",
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/procRoot",
						Type: &hostPathDirectoryType,
					},
				},
				// real-export-dir gives us a directory we can use to export files directly to the host
				{
					Name: "real-export-dir",
					HostPath: &corev1.HostPathVolumeSource{
						Path: "/tetragonExport",
						Type: &hostPathDirectoryType,
					},
				},
			}
			extraKindVolumesBytes, err := yaml.Marshal(extraKindVolumes)
			if err != nil {
				return ctx, fmt.Errorf("failed to marshal extraVolumes: %w", err)
			}
			daemonsetMap[tetragon.AgentExtraVolumesKey] = string(extraKindVolumesBytes)
			extraKindVolumeMounts := []corev1.VolumeMount{
				{
					Name:      "real-host-proc",
					MountPath: "/procRootReal",
				},
				{
					Name:      "real-export-dir",
					MountPath: "/tetragonExport",
				},
			}
			extraKindVolumeMountsBytes, err := yaml.Marshal(extraKindVolumeMounts)
			if err != nil {
				return ctx, fmt.Errorf("failed to marshal extraVolumeMounts: %w", err)
			}
			daemonsetMap["extraVolumeMounts"] = string(extraKindVolumeMountsBytes)
			daemonsetMap["extraArgs"] = "PLACEHOLDER"
		}

		// Installation through OLM
		if ctx, err = helpers.CreateNamespace(o.Namespace, true)(ctx, cfg); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctx, err
			}
		}
		// Create the computed Operator ConfigMap
		cmCMString, err := yaml.Marshal(agentCMMap)
		if err != nil {
			return ctx, fmt.Errorf("failed to marshal the agent ConfigMap part of the operator ConfigMap: %w", err)
		}
		opCM.Data[agent.OperatorConfigMapAgentConfigMapKey] = string(cmCMString)
		dsCMString, err := yaml.Marshal(daemonsetMap)
		if err != nil {
			return ctx, fmt.Errorf("failed to marshal the agent DaemonSet part of the operator ConfigMap: %w", err)
		}
		dsCMStr := string(dsCMString)
		// Workaround as extraArgs is not a literal value
		dsCMStr = strings.ReplaceAll(dsCMStr, " PLACEHOLDER", extraArgs)
		opCM.Data[agent.OperatorConfigMapAgentDaemonSetKey] = dsCMStr
		tetragonRes := client.Resources(o.Namespace)
		if err := tetragonRes.Create(ctx, opCM); err != nil {
			return ctx, fmt.Errorf("failed to create the operator ConfigMap: %w", err)
		}
		ogStr := strings.NewReader(OperatorGroup)
		ogObjects, err := decoder.DecodeAll(ctx, ogStr)
		if err != nil {
			return ctx, err
		}
		if ctx, err = helpers.LoadObjects(o.Namespace, ogObjects, false)(ctx, cfg); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctx, err
			}
		}
		csStr := strings.NewReader(CatalogSource)
		csObjects, err := decoder.DecodeAll(ctx, csStr)
		if err != nil {
			return ctx, err
		}
		// Load the OLM index image into kind cluster if running in kind
		if clusterName := helpers.GetTempKindClusterName(ctx); clusterName != "" {
			// Extract image from CatalogSource spec and load it into kind
			// The CatalogSource YAML is modified by CI to point to the CI-built index image
			var csImage string
			for _, obj := range csObjects {
				// The decoder returns typed CatalogSource objects (not Unstructured) because
				// the OLM scheme is registered. Handle the typed CatalogSource directly.
				if cs, ok := obj.(*operatorsv1alpha1.CatalogSource); ok {
					if cs.Spec.Image != "" {
						csImage = cs.Spec.Image
						break
					}
				}
			}
			if csImage != "" {
				klog.InfoS("Loading OLM index image into kind cluster",
					"cluster", clusterName, "image", csImage)
				var err error
				if ctx, err = envfuncs.LoadDockerImageToCluster(clusterName, csImage)(ctx, cfg); err != nil {
					if strings.Contains(err.Error(), "not present locally") {
						klog.InfoS("OLM index image is not present locally, Kubernetes will attempt to pull it",
							"cluster", clusterName, "image", csImage)
					} else {
						return ctx, fmt.Errorf("failed to load OLM index image %s into cluster %s: %w",
							csImage, clusterName, err)
					}
				} else {
					klog.InfoS("Successfully loaded OLM index image into kind cluster",
						"cluster", clusterName, "image", csImage)
				}
				// OLM's InferImagePullPolicy returns Always for non-digest
				// image references (any ref without "@"). This causes the
				// kubelet to pull from the remote registry even when the
				// image is already present in containerd, resulting in 401
				// errors against registries requiring auth. Rewrite the
				// CatalogSource image to use a digest reference so OLM
				// sets imagePullPolicy:IfNotPresent instead.
				digestImage, digestErr := imageDigestRef(clusterName, csImage)
				if digestErr == nil && digestImage != "" {
					// Tag the image with the digest reference inside the kind
					// node so that containerd's CRI can resolve it.
					nodeName := fmt.Sprintf("%s-control-plane", clusterName)
					tagCmd := exec.Command("docker", "exec", nodeName,
						"ctr", "--namespace=k8s.io", "images", "tag", csImage, digestImage)
					if tagOut, tagErr := tagCmd.CombinedOutput(); tagErr != nil {
						klog.InfoS("Failed to tag image with digest ref in containerd",
							"error", tagErr, "output", string(tagOut))
					}
					for _, obj := range csObjects {
						if cs, ok := obj.(*operatorsv1alpha1.CatalogSource); ok {
							if cs.Spec.Image == csImage {
								cs.Spec.Image = digestImage
								klog.InfoS("Updated CatalogSource image to digest reference",
									"name", cs.Name, "original", csImage, "digest", digestImage)
							}
						}
					}
				} else if digestErr != nil {
					klog.InfoS("Could not resolve image digest, OLM will use Always pull policy",
						"image", csImage, "error", digestErr)
				}
			}
			// Also load the OLM bundle image if provided via env var.
			// OLM's unpack job pulls the bundle image referenced inside
			// the catalog index. Without pre-loading, the pull fails
			// because the kind cluster has no registry credentials.
			if bundleImage := os.Getenv("E2E_OLM_BUNDLE_IMAGE"); bundleImage != "" {
				klog.InfoS("Loading OLM bundle image into kind cluster",
					"cluster", clusterName, "image", bundleImage)
				if ctx, err = envfuncs.LoadDockerImageToCluster(clusterName, bundleImage)(ctx, cfg); err != nil {
					if !strings.Contains(err.Error(), "not present locally") {
						return ctx, fmt.Errorf("failed to load OLM bundle image %s into cluster %s: %w",
							bundleImage, clusterName, err)
					}
				}
				// Rewrite to digest ref so OLM unpack uses IfNotPresent
				if digestBundle, dErr := imageDigestRef(clusterName, bundleImage); dErr == nil && digestBundle != "" {
					nodeName := fmt.Sprintf("%s-control-plane", clusterName)
					tagCmd := exec.Command("docker", "exec", nodeName,
						"ctr", "--namespace=k8s.io", "images", "tag", bundleImage, digestBundle)
					if tagOut, tagErr := tagCmd.CombinedOutput(); tagErr != nil {
						klog.InfoS("Failed to tag bundle image with digest ref",
							"error", tagErr, "output", string(tagOut))
					} else {
						klog.InfoS("Tagged OLM bundle image with digest ref",
							"original", bundleImage, "digest", digestBundle)
					}
				}
			}
		}
		// Create an imagePullSecret for Artifactory if credentials are
		// available. OLM pods (including bundle unpack jobs) need this
		// to pull images from the private registry.
		if artHost := os.Getenv("E2E_ARTIFACTORY_HOST"); artHost != "" {
			artUser := os.Getenv("E2E_ARTIFACTORY_USERNAME")
			artPass := os.Getenv("E2E_ARTIFACTORY_PASSWORD")
			if artUser != "" && artPass != "" {
				secretName := "artifactory-registry"
				csNamespace := "kube-system"
				if secret, sErr := createRegistrySecret(ctx, cfg, csNamespace, secretName, artHost, artUser, artPass); sErr != nil {
					klog.InfoS("Failed to create Artifactory imagePullSecret", "error", sErr)
				} else if secret != nil {
					klog.InfoS("Created Artifactory imagePullSecret", "namespace", csNamespace, "name", secretName)
					// Add the secret to CatalogSource.spec.secrets so OLM
					// sets imagePullSecrets on pods it creates.
					for _, obj := range csObjects {
						if cs, ok := obj.(*operatorsv1alpha1.CatalogSource); ok {
							cs.Spec.Secrets = append(cs.Spec.Secrets, secretName)
							klog.InfoS("Added imagePullSecret to CatalogSource",
								"name", cs.Name, "secret", secretName)
						}
					}
				}
			}
		}
		if ctx, err = helpers.LoadObjects(o.Namespace, csObjects, false)(ctx, cfg); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctx, err
			}
		}
		var subStr *strings.Reader
		if _, ok := o.HelmValues[tetragon.AgentImageKey]; ok {
			tmp := strings.ReplaceAll(Subscription, "env:", fmt.Sprintf("env:\n     - name: TETRAGON_IMAGE\n       value: %s", o.HelmValues[tetragon.AgentImageKey]))
			subStr = strings.NewReader(tmp)
		} else {
			subStr = strings.NewReader(Subscription)
		}
		subObjects, err := decoder.DecodeAll(ctx, subStr)
		if err != nil {
			return ctx, err
		}

		// Not implemented: selecting a specific version by setting the following fields in the subscription
		// installPlanApproval: Manual
		// startingCSV: o.HelmChartsVersion
		// and "manually" approving the InstallPlan
		if ctx, err = helpers.LoadObjects(o.Namespace, subObjects, false)(ctx, cfg); err != nil {
			return ctx, err
		}
		klog.Info("Waiting for Tetragon DaemonSet to be ready...")
		if o.Wait {
			ds := v1.DaemonSet{
				Name:      o.DaemonSetName,
				Namespace: o.Namespace,
			}
			err = wait.For(
				func(_ context.Context) (done bool, err error) {
					if err := tetragonRes.Get(ctx, ds.GetName(), ds.GetNamespace(), &ds); err != nil {
						if apierrors.IsNotFound(err) {
							return false, nil
						}
						return false, err
					}
					if ds.Status.NumberReady != ds.Status.DesiredNumberScheduled {
						return false, nil
					}
					return true, nil
				}, wait.WithTimeout(10*time.Minute))
			if err != nil {
				pods := corev1.PodList{}
				logs := ""
				err = tetragonRes.List(ctx, &pods)
				if err == nil {
					for _, item := range pods.Items {
						klog.Info("Pod name ", item.Name)
						klog.Info("Pod status ", item.Status)
						if strings.HasPrefix(item.Name, "tetragon-operator") {
							klog.Info("Tetragon operator spec ", item.Spec)
							cl, err := clientset.NewForConfig(cfg.Client().RESTConfig())
							if err == nil {
								logs, _ = getPodLogs(ctx, cl, o.Namespace, item.Name, "tetragon-operator", false, nil, nil)
							} else {
								klog.Error("Failed retrieving tetragon operator logs ", err)
							}
						}
					}
				}
				opCM := corev1.ConfigMap{
					Name:      "tetragon-operator-config",
					Namespace: o.Namespace,
				}
				err = tetragonRes.Get(ctx, opCM.GetName(), opCM.GetNamespace(), &opCM)
				if err == nil {
					klog.Info("operator ConfigMap ", opCM)
				}
				aCM := corev1.ConfigMap{
					Name:      "tetragon-config",
					Namespace: o.Namespace,
				}
				err = tetragonRes.Get(ctx, aCM.GetName(), aCM.GetNamespace(), &aCM)
				if err == nil {
					klog.Info("agent ConfigMap ", aCM)
				}
				klog.Info("agent Daemonset ", ds)
				klog.Info("operator logs ", logs)
				return ctx, err
			}
			// The checker mechanism is not tolerant to pod restarts
			// When the daemonset is created it gets updated a few times by the operator
			// before its configuration is stable, which means that the pods are restarted
			// and the checker looses the connection if it was too quick.
			time.Sleep(42 * time.Second)
			klog.Info("Tetragon DaemonSet is ready!")
		}
		return context.WithValue(ctx, state.InstallOpts, o), nil
	}
}

func processOpts(opts ...tetragon.Option) *flags.HelmOptions {
	defaultOpts := flags.Opts.Helm
	for _, opt := range opts {
		opt(&defaultOpts)
	}
	return &defaultOpts
}

func getPodLogs(ctx context.Context, c clientset.Interface, namespace, podName, containerName string, previous bool, sinceTime *metav1.Time, tailLines *int) (string, error) {
	request := c.CoreV1().RESTClient().Get().
		Resource("pods").
		Namespace(namespace).
		Name(podName).SubResource("log").
		Param("container", containerName).
		Param("previous", strconv.FormatBool(previous))
	if sinceTime != nil {
		request.Param("sinceTime", sinceTime.Format(time.RFC3339))
	}
	if tailLines != nil {
		request.Param("tailLines", strconv.Itoa(*tailLines))
	}
	logs, err := request.Do(ctx).Raw()
	if err != nil {
		return "", err
	}
	if strings.Contains(string(logs), "Internal Error") {
		return "", fmt.Errorf("fetched log contains \"internal error\": %q", string(logs))
	}
	return string(logs), err
}

// imageDigestRef queries the kind node's containerd for the digest of the
// given image and returns a reference in the form "repo@sha256:..." so that
// OLM's InferImagePullPolicy selects IfNotPresent instead of Always.
func imageDigestRef(clusterName, image string) (string, error) {
	nodeName := fmt.Sprintf("%s-control-plane", clusterName)
	cmd := exec.Command("docker", "exec", nodeName,
		"ctr", "--namespace=k8s.io", "images", "ls", fmt.Sprintf("name==%s", image))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ctr images ls: %w (output: %s)", err, string(out))
	}
	// Parse the ctr output to extract the digest. Format:
	// REF TYPE DIGEST SIZE ...
	// <image> application/vnd.oci.image.manifest.v1+json sha256:abc... 70.8 MiB ...
	for line := range strings.SplitSeq(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == image {
			digest := fields[2]
			if strings.HasPrefix(digest, "sha256:") {
				// Strip the tag from the image and append the digest.
				repo := image
				if idx := strings.LastIndex(repo, ":"); idx > 0 {
					repo = repo[:idx]
				}
				return repo + "@" + digest, nil
			}
		}
	}
	return "", fmt.Errorf("digest not found for image %s in ctr output", image)
}

// createRegistrySecret creates a docker-registry Secret in the given namespace
// so that OLM pods can authenticate when pulling images from the registry.
func createRegistrySecret(ctx context.Context, cfg *envconf.Config, namespace, name, server, username, password string) (*corev1.Secret, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	dockerCfg := map[string]any{
		"auths": map[string]any{
			server: map[string]string{
				"username": username,
				"password": password,
				"auth":     auth,
			},
		},
	}
	dockerCfgJSON, err := json.Marshal(dockerCfg)
	if err != nil {
		return nil, fmt.Errorf("marshal docker config: %w", err)
	}
	secret := &corev1.Secret{
		Name:      name,
		Namespace: namespace,
		Type:      corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: dockerCfgJSON,
		},
	}
	cl, err := clientset.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}
	created, err := cl.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return secret, nil
	}
	return created, err
}
