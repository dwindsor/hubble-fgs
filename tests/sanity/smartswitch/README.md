# Sanity Test Framework for AGW and SIM

This directory contains sanity tests for AGW (Agent Gateway) and SIM (DPU Simulator) running in Docker containers. All sanity tests require **2 SIM containers** to run.

## Overview

The test framework validates:
- AGW health and basic operations
- SmartSwitchNetworkPolicy management via `agwctl`
- Policy propagation from AGW to multiple SIM dataplanes
- Policy lifecycle (add, verify, remove) across all DPUs
- Rule hash matching between AGW and each SIM
- Policy structure validation
- Packet flow verification on both DPUs
- Kubernetes integration (CRDs, ConfigMap watcher, ServiceAccount auth)
- Prometheus remote-write metrics push
- Hubble Timescape event push

## Structure

```
tests/sanity/smartswitch/
├── README.md                       # This file
├── DEPLOYMENT.md                   # Deployment guide (K8s infra, CI, secrets)
├── Makefile                        # Automated deployment and testing
├── requirements.txt                # Python dependencies
├── pytest.ini                      # Pytest configuration
├── conftest.py                     # Pytest fixtures and configuration
├── scripts/
│   └── launch_sas.sh               # DPU Sim launch script
├── k8s/                            # Kubernetes manifests
│   ├── prometheus.yaml             # Prometheus deployment + service
│   ├── timescape.yaml              # Timescape client ConfigMap (patched at deploy)
│   └── hubble-timescape-values.yaml # Helm values for Timescape chart
├── config/
│   ├── __init__.py
│   └── testing_config.py           # Test configuration (Docker containers)
├── helper/
│   ├── __init__.py
│   ├── command_executor.py         # Docker exec command execution
│   ├── packet_utils.py             # Packet sniffing/sending utilities
│   ├── packet_verification.py      # Packet flow verification
│   ├── policy_generator.py         # Dynamic policy generation
│   ├── verification.py             # Policy verification helpers
│   └── utils.py                    # General utilities
├── parameters/
│   └── test_params.py              # Parameterized test data
├── testdata/
│   └── policies/
│       ├── agw/                    # AGW policy files (YAML)
│       └── dpu/                    # Expected DPU policy files (JSON)
├── test_policy.py                  # Policy lifecycle tests
├── test_policy_rule_manipulation.py # Policy add/update/remove tests
├── test_cidr_range.py              # CIDR range policy + packet flow tests
├── test_port_range.py              # Port/protocol policy + packet flow tests
├── test_policy_multi_dpu.py        # Multi-DPU specific tests
└── dsc/                            # DPU simulator files (auto-generated)
```

## Requirements

- Python 3.12+ (pyenv recommended)
- Docker
- kind ([kind.sigs.k8s.io](https://kind.sigs.k8s.io/))
- kubectl
- helm
- htpasswd (`sudo apt-get install apache2-utils`)
- openssl (usually pre-installed)
- Allure (optional, for reporting)

### Required Environment Variables

```bash
export TIMESCAPE_PASSWORD="your-timescape-password"
export PROMETHEUS_PASSWORD="your-prometheus-password"
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full list of variables and CI secrets.

## Test Environment

### Containers

**AGW Container** (`agw`):
- Runs `agwctl` binary
- Manages SmartSwitchNetworkPolicy resources
- Communicates with SIM container

**SIM Containers** (`naples-{version}-1`, `naples-{version}-2`):
- Two DPU simulator instances (dataplane)
- Each runs `dpctl` for policy inspection
- Each includes FWA functionality
- Both receive policies from AGW independently
- Host uplink interfaces per SIM: `sim{N}-eth1-1`, `sim{N}-eth1-2`, `sim{N}-dsc0`

### Policy Format
- **AGW Format**: `SmartSwitchNetworkPolicy` YAML files
- **SIM Format**: JSON policy structures with rule hashes
- Tests validate both formats match on each DPU container

## Quick Start

### Automated Setup (Recommended)

```bash
cd tests/sanity/smartswitch

# Set required passwords
export TIMESCAPE_PASSWORD="your-timescape-password"
export PROMETHEUS_PASSWORD="your-prometheus-password"

# Launch full stack (AGW + 2 SIMs + K8s infra)
make launch-containers-multi

# Install Python test dependencies
make install-test-dependencies

# Run all tests
sudo make run-all-tests
```

### Manual Setup

If you prefer manual control:

```bash
cd tests/sanity/smartswitch

# Set required passwords
export TIMESCAPE_PASSWORD="your-timescape-password"
export PROMETHEUS_PASSWORD="your-prometheus-password"

# 1. Build AGW image
make build-agw-image

# 2. Pull DPU simulator image
make pull-sim-image

# 3. Launch 2 SIM containers
make launch-sim-multi SIM_COUNT=2

# 4. Launch AGW container (also creates kind cluster + deploys K8s infra)
make launch-agw

# 5. Configure network for all SIMs
make configure-network-multi

# 6. Check status
make show-containers-status-multi

# 7. Install test dependencies
make install-test-dependencies

# 8. Run tests
sudo make run-all-tests
```

### Single DPU Setup

For tests that require only one DPU simulator, use the non-multi targets:

```bash
cd tests/sanity/smartswitch

# Automated: Launch AGW + 1 SIM
make launch-containers

# Or manual steps:
make build-agw-image
make pull-sim-image
make launch-sim
make launch-agw
make configure-network
make show-containers-status

# Cleanup
make shutdown-containers
```

## Running Tests

### Using Makefile (Recommended)

```bash
# Run all tests
make run-all-tests

# Run specific test
make run-specific-test TEST=test_policy.py::test_agw_health

# Run with Allure reporting
make run-tests-with-allure
make show-allure-report
```

### Using pytest Directly

```bash
# Activate virtual environment first
source venv/bin/activate

# Run all tests
pytest -v

# Run with markers
pytest -v -m agw        # Only AGW tests
pytest -v -m policy     # Only policy tests
pytest -v -m "not fwa"  # Skip FWA tests

# Run specific test
pytest -v test_policy.py::test_agw_health
```

## Cleanup

```bash
# Stop and remove all containers + delete kind cluster
make shutdown-containers-multi

# Clean test artifacts
make clean-test-artifacts

# Remove DPU simulator files
rm -rf dsc/
```

## Troubleshooting

### Check Container Status
```bash
make show-containers-status-multi
```

Shows:
- All container names and status (AGW + SIMs)
- Running ports
- Health check results per container

### Containers not running
```bash
# Check Docker containers
docker ps -a | grep -E "agw|naples"

# View container logs
docker logs agw
docker logs naples-1.32.0-1
docker logs naples-1.32.0-2

# Restart containers
make shutdown-containers-multi
make launch-containers-multi
```

### Policy add fails
```bash
# Check AGW health
docker exec agw ./agwctl health

# Verify policy file format
cat testdata/policies/agw/permit_all_simple.yaml

# Check AGW logs
docker logs agw --tail=50
```

### SIM policies not matching AGW
- Check rule hashes in AGW output
- Verify both SIM containers are running: `docker ps | grep naples`
- Check SIM policies on each DPU:
  ```bash
  docker exec naples-1.32.0-1 dpctl hs policies show
  docker exec naples-1.32.0-2 dpctl hs policies show
  ```

### Test collection errors
- Ensure `dsc/` directory is excluded in `pytest.ini`
- Check `norecursedirs = dsc venv .git __pycache__`

### Python venv creation fails
```bash
# If using pyenv
pyenv install 3.12.0
pyenv local 3.12.0

# If ensurepip missing
sudo apt-get install python3-venv  # Ubuntu/Debian
brew install python@3.12            # macOS
```

### Rebuild after code changes
```bash
make shutdown-containers-multi
make build-agw-image
make launch-containers-multi
```

## See Also

- [DEPLOYMENT.md](DEPLOYMENT.md) - Detailed deployment guide (K8s infra, CI pipeline, secrets)
- [Makefile](Makefile) - All available targets
- [SmartSwitchNetworkPolicy Examples](testdata/policies/) - Policy file examples
