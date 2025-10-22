# Smartswitch Test Helm Chart

This Helm chart deploys FWA (Firewall Agent) and AGW (Agent Gateway) test containers in a single pod for scale testing and validation without hardware dependencies.

## Overview

Each pod deployed by this chart contains two containers:
- **AGW Test Container**: Provides a gRPC server listening on port 8880
- **FWA Test Container**: Connects to the AGW container via localhost

Both containers run in headless mode with hardware integrations disabled, making them suitable for:
- Scale testing
- Integration testing
- Development and validation

## Installation

### Basic Installation

Deploy with default values (1 pod in the `smartswitch-test` namespace):

```bash
helm install smartswitch-test ./smartswitch-test
```

### Scale Testing

Deploy multiple pods for scale testing:

```bash
# Deploy 10 pods
helm install smartswitch-test ./smartswitch-test --set replicaCount=10

# Deploy 100 pods
helm install smartswitch-test ./smartswitch-test --set replicaCount=100
```

### Custom Namespace

Deploy to a specific namespace:

```bash
helm install smartswitch-test ./smartswitch-test \
  --set namespace.name=my-test-namespace \
  --set replicaCount=50
```

### Disable Namespace Creation

If you want to deploy to an existing namespace without creating a new one:

```bash
helm install smartswitch-test ./smartswitch-test \
  --namespace existing-namespace \
  --set namespace.create=false
```

## Configuration

### Key Values

| Parameter | Description | Default |
|-----------|-------------|---------|
| `namespace.create` | Create a dedicated namespace | `true` |
| `namespace.name` | Name of the namespace | `smartswitch-test` |
| `replicaCount` | Number of pods to deploy | `1` |
| `agw.image.repository` | AGW container image | `isovalent/agw-test` |
| `agw.image.tag` | AGW container image tag | `latest` |
| `agw.image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `fwa.image.repository` | FWA container image | `isovalent/fwa-test` |
| `fwa.image.tag` | FWA container image tag | `latest` |
| `fwa.image.pullPolicy` | Image pull policy | `IfNotPresent` |

### AGW Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `agw.config` | Path to AGW configuration file | `""` (empty) |
| `agw.networkPolicy` | Path to network policy file | `""` (empty) |
| `agw.enableK8s` | Enable Kubernetes integration | `"true"` |
| `agw.enableNxos` | Enable NXOS integration | `"false"` |
| `agw.dpuServerAddress` | gRPC server listen address | `0.0.0.0:8880` |
| `agw.vrfMap` | VRF mapping configuration | `""` (empty) |
| `agw.debug` | Enable debug logging | `"true"` |
| `agw.k8sServiceAccountAuth` | Kubernetes service account token | `""` (empty) |
| `agw.resources` | Resource limits and requests | `{}` |
| `agw.securityContext` | Security context for container | `{}` |

### FWA Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `fwa.config` | Path to FWA configuration file | `""` (empty) |
| `fwa.networkPolicy` | Path to network policy file | `""` (empty) |
| `fwa.enableDataplane` | Enable dataplane integration | `"false"` |
| `fwa.enableAgw` | Enable AGW client | `"true"` |
| `fwa.enableLogger` | Enable logger integration | `"false"` |
| `fwa.serverAddress` | AGW server address to connect to | `127.0.0.1:8880` |
| `fwa.dpSocketPath` | Dataplane socket path | `""` (empty) |
| `fwa.debug` | Enable debug logging | `"true"` |
| `fwa.resources` | Resource limits and requests | `{}` |
| `fwa.securityContext` | Security context for container | `{}` |

### Service Account Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceAccount.create` | Create a service account | `true` |
| `serviceAccount.automount` | Auto-mount service account credentials | `true` |
| `serviceAccount.annotations` | Annotations for service account | `{}` |
| `serviceAccount.name` | Name of service account to use | `""` (auto-generated) |

### Additional Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `imagePullSecrets` | Image pull secrets for private registries | `[]` |
| `podAnnotations` | Annotations to add to pods | `{}` |
| `podLabels` | Labels to add to pods | `{}` |
| `podSecurityContext` | Security context for pods | `{}` |
| `nodeSelector` | Node selector for pod placement | `{}` |
| `tolerations` | Tolerations for pod scheduling | `[]` |
| `affinity` | Affinity rules for pod scheduling | `{}` |
| `autoscaling.enabled` | Enable autoscaling (not recommended for tests) | `false` |

## Examples

### Example 1: Basic Development Testing (1 pod)

Deploy a single test pod with default settings (debug enabled, K8s integration enabled):

```bash
helm install dev-test ./smartswitch-test \
  --set namespace.name=dev-test
```

### Example 2: AGW with Controller Connection

Deploy with AGW connecting to a Kubernetes controller using a service account token:

```bash
helm install controller-test ./smartswitch-test \
  --set namespace.name=controller-test \
  --set agw.enableK8s=true \
  --set agw.k8sServiceAccountAuth="your-service-account-token-here"
```

**Note**: Replace `your-service-account-token-here` with an actual Kubernetes service account token. This configuration enables AGW to authenticate with and connect to the Kubernetes controller for testing controller integration scenarios.

### Example 3: Headless Testing (No K8s Integration)

Deploy in fully headless mode without any external integrations:

```bash
helm install headless-test ./smartswitch-test \
  --set namespace.name=headless-test \
  --set agw.enableK8s=false \
  --set agw.debug=false \
  --set fwa.debug=false
```

### Example 4: Small Scale Test (10 pods)

```bash
helm install scale-test-10 ./smartswitch-test \
  --set namespace.name=scale-test \
  --set replicaCount=10
```

### Example 5: Large Scale Test (100 pods with resource limits)

```bash
helm install scale-test-100 ./smartswitch-test \
  --set namespace.name=scale-test \
  --set replicaCount=100 \
  --set agw.resources.limits.cpu=500m \
  --set agw.resources.limits.memory=512Mi \
  --set fwa.resources.limits.cpu=500m \
  --set fwa.resources.limits.memory=512Mi
```

### Example 6: Custom Values File

Create a `custom-values.yaml`:

```yaml
namespace:
  name: large-scale-test
  create: true

replicaCount: 200

agw:
  enableK8s: "true"
  debug: "true"
  k8sServiceAccountAuth: "your-token-here"
  resources:
    limits:
      cpu: 500m
      memory: 512Mi
    requests:
      cpu: 250m
      memory: 256Mi

fwa:
  enableAgw: "true"
  debug: "true"
  resources:
    limits:
      cpu: 500m
      memory: 512Mi
    requests:
      cpu: 250m
      memory: 256Mi

# Optional: Image pull secrets for private registries
imagePullSecrets:
  - name: regcred

# Optional: Pod scheduling constraints
nodeSelector:
  kubernetes.io/os: linux

tolerations:
  - key: "node-role.kubernetes.io/control-plane"
    operator: "Exists"
    effect: "NoSchedule"
```

Deploy with:

```bash
helm install large-scale ./smartswitch-test -f custom-values.yaml
```

## Uninstalling

Remove the deployment:

```bash
helm uninstall smartswitch-test
```

If you created a namespace, delete it separately:

```bash
kubectl delete namespace smartswitch-test
```

## Monitoring

Check pod status:

```bash
kubectl get pods -n smartswitch-test
```

View logs for AGW container:

```bash
kubectl logs -n smartswitch-test <pod-name> -c agw-test
```

View logs for FWA container:

```bash
kubectl logs -n smartswitch-test <pod-name> -c fwa-test
```
