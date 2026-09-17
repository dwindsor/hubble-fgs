# Deploying Tetragon with the Operator Lifecycle Manager (OLM)

This directory contains files for packaging the Tetragon Operator as an [OLM bundle](https://sdk.operatorframework.io/docs/olm-integration/tutorial-bundle/).
Such bundles can be published to a catalog and made available for installation and updates 
on Kubernetes clusters, where OLM is available. OLM comes preinstalled with OpenShift.

## Building and pushing an OLM bundle

Set the variables according to your container repository and image version:
```bash
export IMAGE_REPOSITORY=<your-registry>/<your-account>
export DOCKER_IMAGE_TAG=latest
```

And call the make targets at the root of the git repository:
```bash
make bundle-build bundle-push
```

## Deploying the bundle on a cluster

Prerequisites:
- OLM is available on the cluster
- The [operator-sdk CLI](https://sdk.operatorframework.io/docs/installation/) has been installed on your machine
- If OLM needs to be installed (e.g.: in case of kind cluster), run the following command: `operator-sdk olm install`
- To test Tetragon OLM operator changes locally:
  * Build the operator image: `make image-operator`
  * Push the operator image in a registry or load in a cluster
  * Override the operator image reference in the `install/olm/bundle/manifests/tetragon-operator.clusterserviceversion.yaml`
  * Build and push OLM bundle

```bash
kubectl create ns tetragon
operator-sdk run bundle $IMAGE_REPOSITORY/tetragon-operator-bundle:$DOCKER_IMAGE_TAG -n tetragon
```

