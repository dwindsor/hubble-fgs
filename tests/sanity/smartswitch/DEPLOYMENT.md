# Deployment Guide

This document describes the deployment targets available in the Makefile for managing the Docker-based test environment.

## Overview

The Makefile provides automated management of:
- Docker containers (AGW and DPU Simulator)
- Container networking and health checks
- Test environment setup and teardown

## Quick Commands

### Launch Containers
```bash
# Build and launch all containers
make launch-containers
```

### Check Status
```bash
# View container status and health
make show-containers-status
```

### Run Tests
```bash
# Install dependencies and run tests
make install-test-dependencies
make run-all-tests
```

### Clean Up
```bash
# Stop and remove all containers
make shutdown-containers
```

## Detailed Commands

### Container Management

#### 1. Build AGW Container
```bash
make build-agw-image
```
- Builds AGW Docker image from `Dockerfile.agw`
- Includes `agwctl` binary
- Tags as configured AGW_IMAGE

#### 2. Pull DPU Simulator
```bash
make pull-sim-image
```
- Downloads DPU simulator tarball from GitHub releases
- Extracts and loads into Docker
- Auto-detects latest version or uses SIM_VERSION

#### 3. Launch SIM Container
```bash
make launch-sim
```
- Launches DPU simulator using `launch_sas.sh` script
- Creates `naples-{version}` container
- Configures network interfaces

#### 4. Launch AGW Container
```bash
make launch-agw
```
- Starts AGW container (`agw`)
- Connects to SIM container
- Configures environment variables

#### 5. Configure Network
```bash
make configure-network
```
- Sets up host IP alias
- Configures routes between containers
- Ensures connectivity

#### 6. Launch All (Complete Setup)
```bash
make launch-containers
```
- Runs all steps: build-agw-image, pull-sim-image, launch-sim, launch-agw, configure-network
- Shows final status
- Complete one-command setup

#### 7. Stop Containers
```bash
make shutdown-containers
```
- Stops AGW container
- Stops SIM container
- Preserves Docker images for reuse

### Status and Monitoring

#### Check Container Status
```bash
make show-containers-status
```

Shows:
- ✅/❌ Container running status
- ✅/❌ Health check results
- Container ports and networks

Example output:
```
Container Status:
==================
AGW:        ✅ Running (healthy)
SIM:        ✅ Running (naples-1.32.0)

Health Checks:
✅ AGW is healthy
✅ DPU dataplane is running
```

### Testing

#### Install Test Dependencies
```bash
make install-test-dependencies
```
- Creates Python virtual environment
- Installs pytest, allure, and other dependencies
- Only needs to be run once

#### Run All Tests
```bash
make run-all-tests
```
- Runs all tests with pytest
- Shows verbose output
- Generates test reports

#### Run Tests with Allure
```bash
make run-tests-with-allure
make show-allure-report
```
- Generates Allure test reports
- Opens interactive report in browser

### Cleanup

#### Stop Containers
```bash
make shutdown-containers
```
- Stops all running containers
- Removes containers
- Preserves Docker images

#### Clean Test Artifacts
```bash
make clean-test-artifacts
```
- Removes Python venv
- Removes allure-results
- Removes pytest cache

#### Complete Cleanup
```bash
make shutdown-containers
make clean-test-artifacts
rm -rf dsc/
```
- Stops all containers
- Cleans test artifacts
- Removes DPU simulator files

### Advanced Usage

#### Rebuild After Code Changes
```bash
make shutdown-containers
make build-agw-image
make launch-containers
```
- Rebuilds AGW Docker image
- Relaunches all containers with new code
- SIM image is reused (pulled from releases)

#### Custom Container Names
```bash
# Override AGW container name via environment variable
export AGW_CONTAINER=my-agw
make launch-containers

# Note: SIM container name is auto-detected (naples-{version})
```

## Configuration Variables

The Makefile uses these variables (can be overridden):

| Variable | Default | Description |
|----------|---------|-------------|
| `AGW_CONTAINER` | `agw` | AGW container name |
| `VENV` | `venv` | Python virtual environment path |
| `PYTEST` | `venv/bin/pytest` | Pytest executable path |

**Note**: SIM container name is auto-detected as `naples-{version}` and cannot be overridden.

## Workflow Examples

### First Time Setup
```bash
cd tests/sanity

# Launch containers
make launch-containers

# Install test dependencies
make install-test-dependencies

# Run tests
make run-all-tests
```

### Development Workflow
```bash
# Make code changes to AGW
vim ../../cmd/agw/main.go

# Rebuild and restart
make shutdown-containers
make build-agw-image
make launch-containers

# Run tests
make run-all-tests
```

### Daily Testing
```bash
# Check if containers are running
make show-containers-status

# If not running, launch
make launch-containers

# Run tests
make run-all-tests
```

### Cleanup After Testing
```bash
# Stop containers (preserves images)
make shutdown-containers

# Complete cleanup
make clean-test-artifacts
```

## Troubleshooting

### "Container already exists"
```bash
# Stop and remove existing containers
make shutdown-containers

# Launch fresh containers
make launch-containers
```

### "Container not healthy"
```bash
# Check container logs
docker logs agw
docker logs naples-1.32.0

# Restart containers
make shutdown-containers
make launch-containers
```

### "Cannot connect to SIM"
```bash
# Verify SIM container is running
docker ps | grep naples

# Check SIM container name
docker exec naples-1.32.0 dpctl hs policies show

# Restart if needed
make shutdown-containers
make launch-containers
```

### "Tests fail with permission denied"
```bash
# Check pytest.ini excludes dsc/ directory
grep norecursedirs pytest.ini

# Should see: norecursedirs = dsc venv .git __pycache__
```

## Best Practices

1. **Check status first**: Run `make show-containers-status` before testing
2. **Use shutdown-containers between rebuilds**: Preserves images, faster restart
3. **Clean test artifacts regularly**: Run `make clean-test-artifacts` to remove cached files
4. **Monitor container logs**: Use `docker logs` for debugging
5. **Keep DPU simulator files**: Don't delete `dsc/` unless necessary

## Available Makefile Targets

### Container Management
- `launch-containers` - Build and start all containers (complete setup)
- `build-agw-image` - Build AGW container image only
- `pull-sim-image` - Pull DPU simulator image from GitHub
- `launch-sim` - Launch SIM container only
- `launch-agw` - Launch AGW container only
- `configure-network` - Configure networking between containers
- `shutdown-containers` - Stop and remove all containers
- `show-containers-status` - Show container status and health
- `attach-agw` - Attach to AGW container shell
- `attach-sim` - Attach to SIM container shell

### Testing
- `install-test-dependencies` - Install Python test dependencies
- `run-all-tests` - Run all tests
- `run-specific-test TEST=<test>` - Run specific test
- `run-tests-with-allure` - Run tests with Allure reporting
- `show-allure-report` - Show Allure report

### Cleanup
- `shutdown-containers` - Stop and remove containers
- `clean-test-artifacts` - Clean Python venv and test artifacts

### Help
- `help` - Show all available targets with descriptions

## See Also

- [README.md](README.md) - Complete framework documentation
- [Makefile](Makefile) - Full list of available targets with implementation
