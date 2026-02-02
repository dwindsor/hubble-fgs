#  Copyright (C) Isovalent, Inc. - All Rights Reserved.
#
#  NOTICE: All information contained herein is, and remains the property of
#  Isovalent Inc and its suppliers, if any. The intellectual and technical
#  concepts contained herein are proprietary to Isovalent Inc and its suppliers
#  and may be covered by U.S. and Foreign Patents, patents in process, and are
#  protected by trade secret or copyright law.  Dissemination of this information
#  or reproduction of this material is strictly forbidden unless prior written
#  permission is obtained from Isovalent Inc.

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
	@# VRF Mapping: default:1, epbr-1001:1025 (25 VRFs), trmvrf-3001:3075 (75 VRFs)
	@docker run -d \
		--name agw \
		--network host \
		-v /tmp:/tmp \
		-e AGW_CONFIG="" \
		-e AGW_NETWORK_POLICY="" \
		-e AGW_ENABLE_K8S="false" \
		-e AGW_ENABLE_NXOS="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="default:1,tims:2,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003,epbr-1004:1004,epbr-1005:1005,epbr-1006:1006,epbr-1007:1007,epbr-1008:1008,epbr-1009:1009,epbr-1010:1010,epbr-1011:1011,epbr-1012:1012,epbr-1013:1013,epbr-1014:1014,epbr-1015:1015,epbr-1016:1016,epbr-1017:1017,epbr-1018:1018,epbr-1019:1019,epbr-1020:1020,epbr-1021:1021,epbr-1022:1022,epbr-1023:1023,epbr-1024:1024,epbr-1025:1025,trmvrf-3001:3001,trmvrf-3002:3002,trmvrf-3003:3003,trmvrf-3004:3004,trmvrf-3005:3005,trmvrf-3006:3006,trmvrf-3007:3007,trmvrf-3008:3008,trmvrf-3009:3009,trmvrf-3010:3010,trmvrf-3011:3011,trmvrf-3012:3012,trmvrf-3013:3013,trmvrf-3014:3014,trmvrf-3015:3015,trmvrf-3016:3016,trmvrf-3017:3017,trmvrf-3018:3018,trmvrf-3019:3019,trmvrf-3020:3020,trmvrf-3021:3021,trmvrf-3022:3022,trmvrf-3023:3023,trmvrf-3024:3024,trmvrf-3025:3025,trmvrf-3026:3026,trmvrf-3027:3027,trmvrf-3028:3028,trmvrf-3029:3029,trmvrf-3030:3030,trmvrf-3031:3031,trmvrf-3032:3032,trmvrf-3033:3033,trmvrf-3034:3034,trmvrf-3035:3035,trmvrf-3036:3036,trmvrf-3037:3037,trmvrf-3038:3038,trmvrf-3039:3039,trmvrf-3040:3040,trmvrf-3041:3041,trmvrf-3042:3042,trmvrf-3043:3043,trmvrf-3044:3044,trmvrf-3045:3045,trmvrf-3046:3046,trmvrf-3047:3047,trmvrf-3048:3048,trmvrf-3049:3049,trmvrf-3050:3050,trmvrf-3051:3051,trmvrf-3052:3052,trmvrf-3053:3053,trmvrf-3054:3054,trmvrf-3055:3055,trmvrf-3056:3056,trmvrf-3057:3057,trmvrf-3058:3058,trmvrf-3059:3059,trmvrf-3060:3060,trmvrf-3061:3061,trmvrf-3062:3062,trmvrf-3063:3063,trmvrf-3064:3064,trmvrf-3065:3065,trmvrf-3066:3066,trmvrf-3067:3067,trmvrf-3068:3068,trmvrf-3069:3069,trmvrf-3070:3070,trmvrf-3071:3071,trmvrf-3072:3072,trmvrf-3073:3073,trmvrf-3074:3074,trmvrf-3075:3075" \
		-e AGW_DEBUG="true" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="false" \
		-e AGW_TIMESCAPE_PASSWORD="" \
		-e AGW_TIMESCAPE_ENDPOINT="" \
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
			ACTUAL_VERSION=$$(gh release list --repo $(GITHUB_REPO) --limit 10 | grep -v "Draft" | head -1 | awk '{print $$1}'); \
			echo "🔍 Latest published release version: $$ACTUAL_VERSION"; \
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
