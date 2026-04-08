# Deployment Guide

This document describes the deployment targets available in the Makefile for managing the SmartSwitch sanity test environment, including Docker containers and Kubernetes infrastructure.

## Overview

The Makefile provides automated management of:
- **Docker containers**: AGW (Agent Gateway) and DPU Simulator(s)
- **Kubernetes infrastructure**: kind cluster, Prometheus, Hubble Timescape, CRDs
- **Container networking** and health checks
- **Test environment** setup and teardown

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                   Kind Cluster (agw-test)                  │
│                                                           │
│  ┌─────────────────┐  ┌──────────────────────────────┐   │
│  │   monitoring/    │  │     hubble-timescape/         │   │
│  │   Prometheus     │  │     Hubble Timescape (Helm)   │   │
│  │   NodePort:30090 │  │     Ingester NodePort: auto   │   │
│  └─────────────────┘  └──────────────────────────────┘   │
│                                                           │
│  ┌─────────────────┐  ┌──────────────────────────────┐   │
│  │   default/       │  │     hypershield/              │   │
│  │   CRDs + SA     │  │     smartswitch-timescape-     │   │
│  │                  │  │     config (ConfigMap)         │   │
│  └─────────────────┘  └──────────────────────────────┘   │
└───────────────────────────────────────────────────────────┘
        ▲                       ▲
        │ K8s API               │ HTTPS push
        │                       │
┌───────┴───────────────────────┴───────┐
│              AGW Container            │
│  - K8s watcher (policies, configmaps) │
│  - Prometheus remote write            │
│  - Timescape event push               │
│  - DPU management (gRPC)              │
└───────────┬───────────┬───────────────┘
            │           │
     ┌──────┘           └──────┐
     ▼                         ▼
┌──────────┐            ┌──────────┐
│  DPU     │            │  DPU     │
│  SIM #1  │            │  SIM #2  │
└──────────┘            └──────────┘
```

## Prerequisites

### Required Software

| Tool | Purpose | Install |
|------|---------|---------|
| Docker | Container runtime | [docs.docker.com](https://docs.docker.com/engine/install/) |
| kind | Local Kubernetes cluster | [kind.sigs.k8s.io](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) |
| kubectl | Kubernetes CLI | [kubernetes.io](https://kubernetes.io/docs/tasks/tools/) |
| helm | Helm chart deployment | [helm.sh](https://helm.sh/docs/intro/install/) |
| htpasswd | Bcrypt hash generation | `sudo apt-get install apache2-utils` |
| openssl | TLS certificate generation | Usually pre-installed |
| Python 3.12+ | Test framework | [python.org](https://www.python.org/) |

### Required Environment Variables

These must be set before running any target that deploys K8s infrastructure:

| Variable | Description | Example |
|----------|-------------|---------|
| `TIMESCAPE_PASSWORD` | Timescape push API basic auth password | `my-secret-password` |
| `PROMETHEUS_PASSWORD` | Prometheus remote-write basic auth password | `my-prom-password` |

### Optional Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SIM_VERSION` | `latest` | DPU simulator version |
| `SIM_COUNT` | `2` | Number of DPU simulator containers |
| `KIND_CLUSTER_NAME` | `agw-test` | Kind cluster name |
| `PROMETHEUS_USERNAME` | `admin` | Prometheus basic auth username |
| `APPLY_ROUTE` | `0` | Enable DPU bridge routing |
| `GITHUB_REPO` | `cisco-hypershield/hs-dpu-pensando` | DPU simulator GitHub repo |
| `GH_TOKEN` | *(required for pull-sim-image)* | GitHub token for private repo access |

### Docker Registry Access

- **Artifactory** (`artifactory.devhub-cloud.cisco.com`): for AGW base images
- **quay.io** (`quay.io/isovalent-charts-dev`): for Hubble Timescape Helm chart

Run `docker login` for both registries before deploying.

## Quick Start

```bash
cd tests/sanity/smartswitch

# Set required passwords
export TIMESCAPE_PASSWORD="your-timescape-password"
export PROMETHEUS_PASSWORD="your-prometheus-password"

# Launch full stack (AGW + 2 DPU SIMs + K8s infra)
make launch-containers-multi

# Install Python test dependencies
make install-test-dependencies

# Run all tests
sudo make run-all-tests

# Cleanup
make shutdown-containers-multi
```

## Deployment Targets

### Full Stack

```bash
# Launch everything (build + pull + K8s + network)
make launch-containers-multi

# Teardown everything
make shutdown-containers-multi
```

`launch-containers-multi` executes in order:
1. `build-agw-image` — build AGW Docker image
2. `pull-sim-image` — download DPU simulator
3. `launch-sim-multi` — start N DPU simulator containers
4. `launch-agw` — create K8s infra + start AGW container
5. `configure-network-multi` — set up host networking
6. `show-containers-status-multi` — verify health

### AGW Container (`launch-agw`)

This is the main orchestration target. It automatically runs:

1. **`create-kind-cluster`** — creates a kind Kubernetes cluster
2. **`deploy-crds`** — deploys SmartSwitchNetworkPolicy CRD
3. **`deploy-prometheus`** — deploys Prometheus with:
   - Remote-write receiver enabled
   - Basic auth (dynamic bcrypt hash from `PROMETHEUS_PASSWORD`)
   - Self-signed TLS certificate
   - NodePort 30090
4. **`deploy-timescape`** — deploys Hubble Timescape with:
   - Real Helm chart from `quay.io/isovalent-charts-dev/hubble-timescape`
   - ClickHouse backend (lite mode)
   - Auto-rotating TLS certificates
   - Basic auth for push API
   - NodePort service (auto-detected)
   - Client ConfigMap in `hypershield` namespace
5. **`generate-sa-token`** — creates a ServiceAccount with cluster-admin and generates AGW auth token
6. Starts the AGW Docker container with all integrations configured

### Individual K8s Targets

These are called automatically by `launch-agw` but can be run individually for debugging:

```bash
make create-kind-cluster          # Create kind cluster
make deploy-crds                  # Deploy CRDs
make deploy-prometheus            # Deploy Prometheus
make deploy-timescape             # Deploy Timescape
make generate-sa-token            # Generate SA token
make teardown-kind-cluster        # Delete kind cluster only
```

## Testing

```bash
# Install Python dependencies
make install-test-dependencies

# Run all tests
sudo make run-all-tests

# Run specific test file
sudo make run-specific-test TEST=test_agw_metrics.py

# Run specific test case
sudo make run-specific-test TEST=test_policy.py::test_agw_health

# Run with Allure reporting
sudo make run-tests-with-allure
make show-allure-report
```

## CI Pipeline

The sanity tests run in GitHub Actions via the `agw-sanity-tests.yaml` workflow, called from `build-images-agw.yml`.

### GitHub Repository Secrets Required

These secrets must be configured in the `isovalent/hubble-fgs` repo settings:

| Secret Name | Description | Already Exists? |
|-------------|-------------|-----------------|
| `HYPERSHIELD_GH_APP_PEM` | GitHub App PEM for DPU simulator access | Yes |
| `ARTIFACTORY_PASSWORD` | Artifactory registry password | Yes |
| `QUAY_ISOVALENT_CHARTS_DEV_USERNAME` | quay.io charts dev registry username | Yes |
| `QUAY_ISOVALENT_CHARTS_DEV_PASSWORD` | quay.io charts dev registry password | Yes |
| `SMARTSWITCH_TIMESCAPE_PASSWORD` | Timescape push API password for tests | **New** |
| `SMARTSWITCH_PROMETHEUS_PASSWORD` | Prometheus basic auth password for tests | **New** |

### GitHub Repository Variables Required

| Variable Name | Description | Already Exists? |
|---------------|-------------|-----------------|
| `UBUNTU_2404_4CPU_32GB_MEMORY_OPTIMIZED` | Runner label | Yes |
| `ARTIFACTORY_USERNAME` | Artifactory registry username | Yes |
| `HYPERSHIELD_GH_APP_ID` | GitHub App ID for DPU simulator | Yes |
| `VAULT_URL`, `VAULT_METHOD`, `VAULT_NAMESPACE` | Vault config (for Artifactory upload) | Yes |
| `ARTIFACTORY_URL` | Artifactory base URL | Yes |

### CI Workflow Steps

1. Checkout code + setup Python
2. Generate GitHub App token for DPU simulator
3. Install GitHub CLI
4. Docker login (Artifactory + quay.io)
5. Install kind, kubectl, helm, htpasswd
6. Build AGW Docker image
7. Pull DPU simulator image
8. Launch 2 DPU simulator containers + verify health
9. Launch AGW (creates kind cluster, deploys Prometheus, Timescape, CRDs, SA)
10. Configure networking
11. Install test dependencies
12. Run sanity tests with Allure
13. Debug + artifact upload on failure
14. Cleanup

## Troubleshooting

### "TIMESCAPE_PASSWORD is not set"
```bash
export TIMESCAPE_PASSWORD="your-password"
export PROMETHEUS_PASSWORD="your-password"
```

### Timescape NodePort detection fails
```bash
# Check Timescape services
kubectl --kubeconfig /tmp/agw-test-kubeconfig -n hubble-timescape get svc -o wide

# The ingester NodePort is auto-detected from hubble-timescape-ingester service
```

### Timescape pods not ready
```bash
# Check pod status
kubectl --kubeconfig /tmp/agw-test-kubeconfig -n hubble-timescape get pods
kubectl --kubeconfig /tmp/agw-test-kubeconfig -n hubble-timescape describe pods

# Check Helm release
KUBECONFIG=/tmp/agw-test-kubeconfig helm list -n hubble-timescape
```

### Prometheus auth fails
```bash
# Verify the secret was created
kubectl --kubeconfig /tmp/agw-test-kubeconfig -n monitoring get secret prometheus-auth -o yaml

# Test basic auth
curl -k -u admin:$PROMETHEUS_PASSWORD https://<kind-node-ip>:30090/-/ready
```

### Kind cluster issues
```bash
# Check cluster
kind get clusters
kubectl --kubeconfig /tmp/agw-test-kubeconfig cluster-info

# Recreate
make teardown-kind-cluster
make create-kind-cluster
```

### Container not healthy
```bash
docker logs agw --tail=50
docker logs naples-1.147.0-1 --tail=50
```

### Rebuild after code changes
```bash
make shutdown-containers-multi
make build-agw-image
make launch-containers-multi
```

## Available Makefile Targets

### Container Management
- `launch-containers-multi` — Full stack with N DPU SIMs
- `launch-containers` — Full stack with 1 DPU SIM
- `shutdown-containers-multi` — Stop all + delete kind cluster
- `shutdown-containers` — Stop AGW + 1 SIM + delete kind cluster
- `show-containers-status-multi` — Status and health for all containers
- `build-agw-image` — Build AGW Docker image
- `pull-sim-image` — Download DPU simulator
- `launch-agw` — Set up K8s infra + start AGW
- `launch-sim-multi` — Launch N DPU simulator containers
- `configure-network-multi` — Configure networking
- `attach-agw` / `attach-sim` — Shell into containers

### K8s Infrastructure
- `create-kind-cluster` — Create kind cluster
- `deploy-crds` — Deploy SmartSwitchNetworkPolicy CRD
- `deploy-prometheus` — Deploy Prometheus remote-write receiver
- `deploy-timescape` — Deploy Hubble Timescape via Helm chart
- `generate-sa-token` — Create ServiceAccount + token
- `teardown-kind-cluster` — Delete kind cluster only

### Testing
- `install-test-dependencies` — Create venv + install packages
- `run-all-tests` — Run all sanity tests
- `run-specific-test TEST=<test>` — Run specific test
- `run-tests-with-allure` — Run with Allure reporting
- `show-allure-report` — Open Allure report

### Cleanup
- `clean-test-artifacts` — Remove venv, reports, cache

## See Also

- [README.md](README.md) — Test framework overview
- [Makefile](Makefile) — All targets with implementation
- [k8s/](k8s/) — Kubernetes manifests (Prometheus, Timescape ConfigMap, values)
