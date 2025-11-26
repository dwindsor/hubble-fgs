# Sanity Test Framework for AGW and SIM

This directory contains sanity tests for AGW (Agent Gateway) and SIM (DPU Simulator) running in Docker containers.

## Overview

The test framework validates:
- AGW health and basic operations
- SmartSwitchNetworkPolicy management via `agwctl`
- Policy propagation from AGW to SIM dataplane
- Policy lifecycle (add, verify, remove)
- Rule hash matching between AGW and SIM
- Policy structure validation

## Structure

```
tests/sanity/
├── README.md                   # This file
├── DEPLOYMENT.md               # Deployment guide
├── Makefile                    # Automated deployment and testing
├── requirements.txt            # Python dependencies
├── pytest.ini                  # Pytest configuration
├── conftest.py                 # Pytest fixtures and configuration
├── config/
│   ├── __init__.py
│   └── testing_config.py       # Test configuration (Docker containers)
├── helper/
│   ├── __init__.py
│   ├── command_executor.py     # Docker exec command execution
│   ├── commands.py             # AGWCTL/DPCTL command definitions
│   └── verification.py         # Test verification helpers
├── testdata/
│   └── policies/
│       ├── agw/                # AGW policy files (YAML)
│       └── dpu/                # Expected DPU policy files (JSON)
├── test_policy.py              # Policy lifecycle tests
└── dsc/                        # DPU simulator files (auto-generated)
```

## Requirements

- Python 3.12+ (pyenv recommended)
- Docker
- Docker Compose (optional)
- Allure (optional, for reporting)

## Test Environment

### Containers

**AGW Container** (`agw`):
- Runs `agwctl` binary
- Manages SmartSwitchNetworkPolicy resources
- Communicates with SIM container

**SIM Container** (`naples-{version}`):
- DPU simulator (dataplane)
- Runs `dpctl` for policy inspection
- Includes FWA functionality
- Receives policies from AGW

### Policy Format
- **AGW Format**: `SmartSwitchNetworkPolicy` YAML files
- **SIM Format**: JSON policy structures with rule hashes
- Test validates both formats match

## Quick Start

### Automated Setup (Recommended)

```bash
cd tests/sanity

# Launch Docker containers (AGW + SIM)
make launch-containers

# Install Python test dependencies
make install-test-dependencies

# Run all tests
make run-all-tests
```

### Manual Setup

If you prefer manual control:

```bash
cd tests/sanity

# 1. Build AGW image
make build-agw-image

# 2. Pull DPU simulator image
make pull-sim-image

# 3. Launch SIM container
make launch-sim

# 4. Launch AGW container
make launch-agw

# 5. Configure network
make configure-network

# 6. Check status
make show-containers-status

# 7. Install test dependencies
make install-test-dependencies

# 8. Run tests
make run-all-tests
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
# Stop and remove all containers
make shutdown-containers

# Clean test artifacts
make clean-test-artifacts

# Remove DPU simulator files
rm -rf dsc/
```

## Troubleshooting

### Check Container Status
```bash
make show-containers-status
```

Shows:
- Container names and status
- Running ports
- Health check results

### Containers not running
```bash
# Check Docker containers
docker ps -a | grep -E "agw|naples"

# View container logs
docker logs agw
docker logs naples-1.32.0

# Restart containers
make shutdown-containers
make launch-containers
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
- Verify SIM container is running: `docker ps | grep naples`
- Check SIM policies: `docker exec naples-1.32.0 dpctl hs policies show`

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
make shutdown-containers
make build-agw-image
make launch-containers
```

## See Also

- [DEPLOYMENT.md](DEPLOYMENT.md) - Detailed deployment guide
- [Makefile](Makefile) - All available targets
- [SmartSwitchNetworkPolicy Examples](testdata/policies/) - Policy file examples
