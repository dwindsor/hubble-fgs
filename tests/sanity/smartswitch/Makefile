.PHONY: help \
        install-test-dependencies run-all-tests \
        run-tests-with-allure show-allure-report run-specific-test \
        clean-test-artifacts \
        launch-containers build-agw-image pull-sim-image launch-agw configure-network shutdown-containers \
        launch-sim attach-sim attach-agw show-containers-status

# Configuration
REPO_ROOT := $(shell cd ../../.. && pwd)
AGW_IMAGE := isovalent/agw-test:latest

# DPU Sim configuration
GITHUB_REPO ?= cisco-hypershield/hs-dpu-pensando
SIM_VERSION ?= latest
# Extract clean version for script compatibility
CLEAN_VERSION := $(shell echo "$(SIM_VERSION)" | sed 's/^v//')
# Dynamically determine VER based on what's available
VER ?= $(shell docker images hypershield/naples --format "{{.Tag}}" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' | head -1 || echo "$(CLEAN_VERSION)")
DSC_INSTANCE ?= naples-$(VER)
TIMEOUT ?= 180
HOST_AGW_IP ?= 169.254.101.2
APPLY_ROUTE ?= 0

# Test configuration
VENV := venv
VENV_BIN := $(VENV)/bin
PYTEST := $(VENV_BIN)/pytest

# ============================================================================
# Help
# ============================================================================

help:
	@echo "AGW/FWA Sanity Test Framework"
	@echo "=============================="
	@echo ""
	@echo "Container Targets:"
	@echo "  launch-containers          - Build AGW + pull DPU + run containers + configure network"
	@echo "  shutdown-containers        - Stop and remove both containers"
	@echo "  show-containers-status     - Show status and health of all containers"
	@echo ""
	@echo "AGW Targets:"
	@echo "  build-agw-image            - Build AGW image only"
	@echo "  launch-agw                 - Run AGW container only"
	@echo "  attach-agw                 - Attach to running AGW container"
	@echo ""
	@echo "DPU Sim Targets:"
	@echo "  pull-sim-image             - Download DPU Sim tarball from GitHub releases"
	@echo "  launch-sim                 - Launch DPU Sim container using launch_sas.sh"
	@echo "  attach-sim                 - Attach to running DPU Sim container"
	@echo ""
	@echo "Network Configuration:"
	@echo "  configure-network          - Configure host IP and DPU interface"
	@echo ""
	@echo "Test Targets:"
	@echo "  install-test-dependencies  - Create venv and install Python packages"
	@echo "  run-all-tests              - Execute all sanity tests"
	@echo "  run-tests-with-allure      - Execute all tests and generate Allure report"
	@echo "  show-allure-report         - Open Allure report in browser"
	@echo "  run-specific-test          - Run specific test (TEST=test_file::test_name)"
	@echo ""
	@echo "Utility Targets:"
	@echo "  clean-test-artifacts       - Remove venv, reports, and cache files"
	@echo ""
	@echo "Configuration Options:"
	@echo "  SIM_VERSION=v1.32.0        - Specific release version (default: latest)"
	@echo "  GITHUB_REPO=org/repo       - GitHub repository (default: cisco-hypershield/hs-dpu-pensando)"
	@echo "  APPLY_ROUTE=1              - Enable DPU bridge routing (default: 0)"
	@echo ""
	@echo "Quick Start:"
	@echo "  make launch-containers     - Start AGW + DPU Sim integration"
	@echo "  make install-test-dependencies - Install test dependencies"
	@echo "  make run-all-tests         - Run tests"
	@echo "  make shutdown-containers   - Stop containers"


# ============================================================================
# AGW Targets
# ============================================================================

build-agw-image:
	@echo "Building AGW image: $(AGW_IMAGE)"
	@cd $(REPO_ROOT) && docker build -f Dockerfile.agw -t $(AGW_IMAGE) .

launch-agw:
	@echo "Starting AGW container..."
	@-docker rm -f agw >/dev/null 2>&1 || true
	@docker run -d \
		--name agw \
		--network host \
		-v /tmp:/tmp \
		-e AGW_CONFIG="" \
		-e AGW_NETWORK_POLICY="" \
		-e AGW_ENABLE_K8S="false" \
		-e AGW_ENABLE_NXOS="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="" \
		-e AGW_DEBUG="true" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		$(AGW_IMAGE)

attach-agw:
	@echo "Attaching to AGW container: agw"
	@docker exec -it agw sh

# ============================================================================
# DPU Sim Targets
# ============================================================================

pull-sim-image:
	@echo "Downloading DPU Sim tarball from GitHub releases: $(GITHUB_REPO)"
	@if command -v gh >/dev/null 2>&1; then \
		if [ "$(SIM_VERSION)" = "latest" ]; then \
			ACTUAL_VERSION=$$(gh release list --repo $(GITHUB_REPO) --limit 1 | awk '{print $$1}'); \
			echo "🔍 Latest release version: $$ACTUAL_VERSION"; \
		else \
			ACTUAL_VERSION=$(SIM_VERSION); \
		fi; \
		CLEAN_VERSION=$$(echo "$$ACTUAL_VERSION" | sed 's/^v//'); \
		TARBALL_NAME="naples-docker-$$CLEAN_VERSION.tgz"; \
		TARBALL_PATH="/tmp/$$TARBALL_NAME"; \
		if [ -f "$$TARBALL_PATH" ]; then \
			echo "✅ Tarball already exists: $$TARBALL_PATH"; \
		else \
			echo "📥 Downloading tarball: $$TARBALL_NAME"; \
			if gh release download "$$ACTUAL_VERSION" --repo $(GITHUB_REPO) --pattern "$$TARBALL_NAME" --dir /tmp 2>/dev/null; then \
				echo "✅ Successfully downloaded: $$TARBALL_PATH"; \
			else \
				echo "❌ Failed to download $$TARBALL_NAME from GitHub releases"; \
				echo "Check if version $$ACTUAL_VERSION exists or install 'gh' CLI"; \
				exit 1; \
			fi; \
		fi; \
	else \
		echo "❌ GitHub CLI 'gh' not found. Please install it first"; \
		exit 1; \
	fi

launch-sim:
	@echo "Launching DPU Sim using original launch_sas.sh script"
	@# Kill any existing containers using DPU ports
	@-docker kill $$(docker ps -a -q --filter expose=11357-11363/tcp) >/dev/null 2>&1 || true
	@# Determine version from downloaded tarball
	@ACTUAL_VER=$$(ls -1 /tmp/naples-docker-*.tgz 2>/dev/null | sed 's|/tmp/naples-docker-||; s|.tgz$$||' | sort -V | tail -1); \
	if [ -z "$$ACTUAL_VER" ]; then \
		echo "❌ No DPU Sim tarball found in /tmp/"; \
		echo "Run 'make pull-sim-image' first to download the tarball"; \
		exit 1; \
	fi; \
	SCRIPT_TARBALL="/tmp/naples-docker-$$ACTUAL_VER.tgz"; \
	echo "Version: $$ACTUAL_VER"; \
	echo "Container: naples-$$ACTUAL_VER"; \
	echo "Timeout: $(TIMEOUT)s"; \
	echo "📋 Using tarball: $$SCRIPT_TARBALL"; \
	chmod +x scripts/launch_sas.sh; \
	sudo NO_ADS=1 \
		DPUIMG="$$SCRIPT_TARBALL" \
		TIMEOUT=$(TIMEOUT) \
		VER="$$ACTUAL_VER" \
		bash scripts/launch_sas.sh; \
	LAUNCH_EXIT=$$?; \
	echo "Launch script exited with code: $$LAUNCH_EXIT"; \
	sleep 3; \
	if docker ps | grep -q "naples-$$ACTUAL_VER"; then \
		echo "✅ Container naples-$$ACTUAL_VER is running"; \
		exit 0; \
	else \
		echo "❌ Container naples-$$ACTUAL_VER failed to start"; \
		docker ps -a | grep naples || echo "No naples containers found"; \
		exit 1; \
	fi

attach-sim:
	@echo "Attaching to DPU Sim container: $(DSC_INSTANCE)"
	@docker exec -it $(DSC_INSTANCE) bash

# ============================================================================
# Container Management Targets
# ============================================================================

launch-containers: build-agw-image pull-sim-image launch-sim launch-agw configure-network show-containers-status
	@echo "Stack ready"

shutdown-containers:
	@echo "Stopping containers..."
	@echo "Stopping AGW container..."
	@-docker rm -f agw >/dev/null 2>&1 || true
	@echo "Stopping DPU Sim container..."
	@-docker rm -f $(DSC_INSTANCE) >/dev/null 2>&1 || true
	@echo "✅ All containers stopped"

configure-network:
	@echo "Configuring host IP alias $(HOST_AGW_IP) (Ubuntu)"
	@sh -c 'if ! ip addr show lo | grep -q "$(HOST_AGW_IP)"; then sudo ip addr add $(HOST_AGW_IP)/32 dev lo; else echo "IP already configured"; fi'
	@if [ "$(APPLY_ROUTE)" = "1" ]; then \
		echo "Configuring DPU route to AGW IP via Docker bridge"; \
		BRIDGE_IP=$$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'); \
		docker exec $(DSC_INSTANCE) ip route add $(HOST_AGW_IP) via $$BRIDGE_IP 2>/dev/null || echo "Route already exists"; \
	else \
		echo "Skipping DPU bridge route (APPLY_ROUTE=0)"; \
	fi
	@echo "Creating DPU mgmt alias int_mnic0 to satisfy FWA (idempotent)"
	@docker exec $(DSC_INSTANCE) sh -c 'ip link show int_mnic0 >/dev/null 2>&1 || ip link add int_mnic0 type dummy'
	@docker exec $(DSC_INSTANCE) sh -c 'ip addr show dev int_mnic0 | grep -q "127.0.0.1/32" || ip addr add 127.0.0.1/32 dev int_mnic0'
	@docker exec $(DSC_INSTANCE) sh -c 'ip link set int_mnic0 up || true'

show-containers-status:
	@echo "Container Status:"
	@docker ps --filter "name=agw" --filter "name=naples-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "No containers running"
	@echo ""
	@echo "Health Checks:"
	@# AGW health
	@if docker ps --filter "name=agw" --format "{{.Names}}" | grep -q agw; then \
		docker exec agw ./agwctl health >/dev/null 2>&1 && echo "✅ AGW is healthy" || echo "❌ AGW health check failed"; \
	else \
		echo "❌ AGW not running"; \
	fi
	@# DPU health
	@DPU_CONTAINER=$$(docker ps --filter "name=naples-" --format "{{.Names}}" | head -1); \
	if [ -n "$$DPU_CONTAINER" ]; then \
		docker exec "$$DPU_CONTAINER" pgrep -f "pds_dp_app" >/dev/null 2>&1 && echo "✅ DPU dataplane is running" || echo "❌ DPU dataplane not running"; \
	else \
		echo "❌ DPU not running"; \
	fi

# ============================================================================
# Test Targets
# ============================================================================

install-test-dependencies:
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv $(VENV); \
		echo "✅ Virtual environment created"; \
	else \
		echo "✅ Virtual environment already exists"; \
	fi
	@echo "Installing dependencies..."
	@$(VENV_BIN)/pip install --upgrade pip
	@$(VENV_BIN)/pip install --upgrade -r requirements.txt
	@echo "✅ Installation complete. Activate venv with: source $(VENV_BIN)/activate"

run-all-tests:
	$(PYTEST) -v

run-tests-with-allure:
	$(PYTEST) -v --alluredir=allure-results

show-allure-report:
	allure serve allure-results

# Run specific test
run-specific-test:
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make run-specific-test TEST=test_policy.py::test_agw_health"; \
	else \
		$(PYTEST) -v $(TEST); \
	fi

# ============================================================================
# Utility Targets
# ============================================================================

clean-test-artifacts:
	rm -rf $(VENV)
	rm -rf allure-results
	rm -rf .pytest_cache
	rm -rf __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
