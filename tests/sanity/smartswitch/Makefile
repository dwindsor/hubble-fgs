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
        install-test-dependencies run-all-tests run-nxos-tests run-ha-tests \
        run-tests-with-allure show-allure-report run-specific-test \
        clean-test-artifacts \
        build-agw-image pull-sim-image build-fwa-image \
        launch-agw launch-sim launch-sim-multi launch-ha-agw \
        launch-containers launch-containers-multi \
        configure-network configure-network-multi \
        attach-agw attach-sim attach-fwa \
        shutdown shutdown-containers shutdown-containers-multi status \
        show-containers-status show-containers-status-multi \
        create-ha-network remove-ha-network \
		create-fwa-network remove-fwa-network create-fwa-ha-network remove-fwa-ha-network \
		launch-fwa-agw launch-fwa seed-fwa-gnmi seed-fwa-ha-gnmi configure-fwa-network launch-containers-fwa \
		launch-fwa-ha-agw launch-fwa-ha configure-fwa-ha-network launch-containers-fwa-ha \
        shutdown-ha-containers show-ha-status \
        create-kind-cluster deploy-crds deploy-prometheus deploy-timescape generate-sa-token teardown-kind-cluster

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
SIM_COUNT ?= 2
TIMEOUT ?= 180
HOST_AGW_IP ?= 169.254.101.2
APPLY_ROUTE ?= 0

# HA configuration (leader = lowest IP, wins election)
HA_NETWORK := ha-net
HA_SUBNET := 172.20.0.0/24
AGW_LEADER_IP := 172.20.0.2
AGW_FOLLOWER_IP := 172.20.0.3
AGW_LEADER_NAME := agw-leader
AGW_FOLLOWER_NAME := agw-follower

# FWA test container configuration
FWA_IMAGE := isovalent/fwa-test:latest
FWA_CONTAINER_PREFIX := fwa-test
FWA_COUNT ?= 2
FWA_NETWORK := fwa-net
FWA_SUBNET := 169.254.0.0/16
FWA_AGW_NAME := agw-fwa
FWA_AGW_IP := 169.254.101.2

# FWA HA configuration
FWA_HA_NETWORK := fwa-ha-net
FWA_HA_AGW_LEADER_NAME := agw-fwa-leader
FWA_HA_AGW_FOLLOWER_NAME := agw-fwa-follower
FWA_HA_AGW_LEADER_IP := 169.254.101.2
FWA_HA_AGW_FOLLOWER_IP := 169.254.101.3

# DPU IPs from DPUMap (pkg/model/switchpolicy/dpu.go)
FWA_DPU_IPS := 169.254.28.1 169.254.24.1 169.254.36.1 169.254.32.1

# Test configuration
VENV := venv
VENV_BIN := $(VENV)/bin
PYTEST := $(VENV_BIN)/pytest

# K8s infrastructure configuration (used by launch-agw)
KIND_CLUSTER_NAME ?= agw-test
KIND_KUBECONFIG := /tmp/$(KIND_CLUSTER_NAME)-kubeconfig
K8S_NAMESPACE ?= default
K8S_SA_NAME ?= smartswitch
CRD_PATH := $(REPO_ROOT)/install/kubernetes/tetragon/crds-yaml/isovalent.com_smartswitchnetworkpolicies.yaml
K8S_MANIFESTS_DIR := $(CURDIR)/k8s
TIMESCAPE_PASSWORD ?= $(error TIMESCAPE_PASSWORD is not set. Export it or pass via env)
PROMETHEUS_USERNAME ?= admin
PROMETHEUS_PASSWORD ?= $(error PROMETHEUS_PASSWORD is not set. Export it or pass via env)
TIMESCAPE_CHART_OCI := oci://quay.io/isovalent-charts-dev/hubble-timescape
TIMESCAPE_CHART_VERSION ?= 1.19.0-dev.177-7ba479660-20260331135043-main
TIMESCAPE_VALUES := $(K8S_MANIFESTS_DIR)/hubble-timescape-values.yaml

# AGW VRF mapping (shared across all launch targets)
AGW_VRF_MAP := default:1,tims:2,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003,epbr-1004:1004,epbr-1005:1005,epbr-1006:1006,epbr-1007:1007,epbr-1008:1008,epbr-1009:1009,epbr-1010:1010,epbr-1011:1011,epbr-1012:1012,epbr-1013:1013,epbr-1014:1014,epbr-1015:1015,epbr-1016:1016,epbr-1017:1017,epbr-1018:1018,epbr-1019:1019,epbr-1020:1020,epbr-1021:1021,epbr-1022:1022,epbr-1023:1023,epbr-1024:1024,epbr-1025:1025,trmvrf-3001:3001,trmvrf-3002:3002,trmvrf-3003:3003,trmvrf-3004:3004,trmvrf-3005:3005,trmvrf-3006:3006,trmvrf-3007:3007,trmvrf-3008:3008,trmvrf-3009:3009,trmvrf-3010:3010,trmvrf-3011:3011,trmvrf-3012:3012,trmvrf-3013:3013,trmvrf-3014:3014,trmvrf-3015:3015,trmvrf-3016:3016,trmvrf-3017:3017,trmvrf-3018:3018,trmvrf-3019:3019,trmvrf-3020:3020,trmvrf-3021:3021,trmvrf-3022:3022,trmvrf-3023:3023,trmvrf-3024:3024,trmvrf-3025:3025,trmvrf-3026:3026,trmvrf-3027:3027,trmvrf-3028:3028,trmvrf-3029:3029,trmvrf-3030:3030,trmvrf-3031:3031,trmvrf-3032:3032,trmvrf-3033:3033,trmvrf-3034:3034,trmvrf-3035:3035,trmvrf-3036:3036,trmvrf-3037:3037,trmvrf-3038:3038,trmvrf-3039:3039,trmvrf-3040:3040,trmvrf-3041:3041,trmvrf-3042:3042,trmvrf-3043:3043,trmvrf-3044:3044,trmvrf-3045:3045,trmvrf-3046:3046,trmvrf-3047:3047,trmvrf-3048:3048,trmvrf-3049:3049,trmvrf-3050:3050,trmvrf-3051:3051,trmvrf-3052:3052,trmvrf-3053:3053,trmvrf-3054:3054,trmvrf-3055:3055,trmvrf-3056:3056,trmvrf-3057:3057,trmvrf-3058:3058,trmvrf-3059:3059,trmvrf-3060:3060,trmvrf-3061:3061,trmvrf-3062:3062,trmvrf-3063:3063,trmvrf-3064:3064,trmvrf-3065:3065,trmvrf-3066:3066,trmvrf-3067:3067,trmvrf-3068:3068,trmvrf-3069:3069,trmvrf-3070:3070,trmvrf-3071:3071,trmvrf-3072:3072,trmvrf-3073:3073,trmvrf-3074:3074,trmvrf-3075:3075

# ============================================================================
# Help
# ============================================================================

help:
	@echo "AGW/FWA Sanity Test Framework"
	@echo "=============================="
	@echo ""
	@echo "Container Lifecycle:"
	@echo "  launch-agw              - AGW with K8s infra (kind + Prometheus + Timescape)"
	@echo "  launch-ha-agw           - Dual AGW HA containers (ha-net, NX-OS mock enabled)"
	@echo "  launch-sim              - Single DPU Sim container"
	@echo "  launch-sim-multi        - Multiple DPU Sim containers (SIM_COUNT=N)"
	@echo "  launch-containers       - Full stack: single AGW + SIM + network config"
	@echo "  launch-containers-multi - Full stack: single AGW + N SIMs + network config"
	@echo "  launch-fwa-agw          - AGW for FWA on bridge network"
	@echo "  launch-fwa              - N FWA test containers (default: 2, use FWA_COUNT=N)"
	@echo "  launch-fwa-ha-agw       - Dual AGW HA containers for FWA"
	@echo "  launch-containers-fwa   - Full FWA stack: AGW + N FWAs (works on arm64/macOS)"
	@echo "  launch-containers-fwa-ha - Full FWA HA stack: 2 AGWs + N FWAs"
	@echo "  shutdown                - Stop all containers and clean up networks"
	@echo "  shutdown-ha-containers  - Stop HA containers and remove HA network"
	@echo "  show-ha-status          - Show status of HA containers"
	@echo "  status                  - Show status and health of running containers"
	@echo ""
	@echo "Build:"
	@echo "  build-agw-image         - Build AGW test image"
	@echo "  build-fwa-image         - Build FWA test image (multi-arch, no tarball needed)"
	@echo "  pull-sim-image          - Download DPU Sim tarball from GitHub releases"
	@echo ""
	@echo "K8s Infrastructure (used by launch-agw):"
	@echo "  create-kind-cluster     - Create kind cluster"
	@echo "  deploy-crds             - Deploy SmartSwitchNetworkPolicy CRDs"
	@echo "  deploy-prometheus       - Deploy Prometheus remote-write receiver"
	@echo "  deploy-timescape        - Deploy Hubble Timescape via Helm chart"
	@echo "  generate-sa-token       - Create ServiceAccount and generate token"
	@echo "  teardown-kind-cluster   - Delete kind cluster only"
	@echo ""
	@echo "Tests:"
	@echo "  run-all-tests           - All sanity tests"
	@echo "  run-nxos-tests          - NX-OS mock store/trigger tests (single AGW)"
	@echo "  run-ha-tests            - HA dual-AGW tests"
	@echo "  run-specific-test       - Run specific test (TEST=test_file::test_name)"
	@echo "  run-tests-with-allure   - Run all tests and generate Allure report"
	@echo "  show-allure-report      - Open Allure report in browser"
	@echo ""
	@echo "Utility:"
	@echo "  install-test-dependencies - Create venv and install Python packages"
	@echo "  clean-test-artifacts    - Remove venv, reports, and cache files"
	@echo "  attach-agw              - Attach shell to AGW container"
	@echo "  attach-sim              - Attach shell to DPU Sim container"
	@echo "  attach-fwa              - Attach shell to FWA test container"
	@echo "  configure-network       - Configure host IP and DPU interface (single SIM)"
	@echo "  configure-network-multi - Configure host IP and DPU interfaces (multi SIM)"
	@echo "  configure-fwa-network   - Configure int_mnic0 for FWA containers"
	@echo "  configure-fwa-ha-network - Configure int_mnic0 for FWA HA containers"
	@echo ""
	@echo "Configuration:"
	@echo "  SIM_VERSION=v1.32.0     - Specific release version (default: latest)"
	@echo "  SIM_COUNT=2             - Number of SIMs for *-multi targets (default: 2)"
	@echo "  FWA_COUNT=2             - Number of FWAs for FWA targets (default: 2)"
	@echo "  GITHUB_REPO=org/repo    - GitHub repository (default: cisco-hypershield/hs-dpu-pensando)"
	@echo "  APPLY_ROUTE=1           - Enable DPU bridge routing (default: 0)"
	@echo ""
	@echo "Required Environment Variables (for K8s infra targets):"
	@echo "  TIMESCAPE_PASSWORD      - Timescape push API password"
	@echo "  PROMETHEUS_PASSWORD     - Prometheus basic auth password"
	@echo ""
	@echo "Quick Start (integration):"
	@echo "  make launch-containers && make install-test-dependencies && make run-all-tests"
	@echo ""
	@echo "Quick Start (HA):"
	@echo "  make launch-ha-agw && make install-test-dependencies && make run-ha-tests"
	@echo ""
	@echo "Quick Start (FWA - works on arm64/macOS):"
	@echo "  make launch-containers-fwa && make install-test-dependencies && make run-all-tests"
	@echo ""
	@echo "Quick Start (HA + FWA):"
	@echo "  make launch-containers-fwa-ha && make install-test-dependencies && make run-ha-tests"


# ============================================================================
# Build
# ============================================================================

build-agw-image:
	@echo "Building AGW image: $(AGW_IMAGE)"
	@cd $(REPO_ROOT) && docker build -f Dockerfile.agw -t $(AGW_IMAGE) --target=agw-test .

launch-agw: create-kind-cluster deploy-crds deploy-prometheus deploy-timescape generate-sa-token
	@echo "Starting AGW container with K8s + Prometheus + Timescape..."
	@AGW_TOKEN="$(AGW_SA_TOKEN)"; \
	if [ -z "$$AGW_TOKEN" ] && [ -f /tmp/$(KIND_CLUSTER_NAME)-agw-token ]; then \
		AGW_TOKEN=$$(cat /tmp/$(KIND_CLUSTER_NAME)-agw-token); \
	fi; \
	if [ -z "$$AGW_TOKEN" ]; then \
		echo "❌ No SA token found. Run 'make generate-sa-token' first."; \
		exit 1; \
	fi; \
	KIND_NODE_IP=$$(docker inspect $(KIND_CLUSTER_NAME)-control-plane -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo '127.0.0.1'); \
	TIMESCAPE_NODEPORT=$$(cat /tmp/$(KIND_CLUSTER_NAME)-timescape-nodeport 2>/dev/null || \
		kubectl --kubeconfig $(KIND_KUBECONFIG) -n hubble-timescape get svc hubble-timescape-ingester -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || \
		echo '30869'); \
	echo "Kind node IP: $$KIND_NODE_IP"; \
	echo "Timescape NodePort: $$TIMESCAPE_NODEPORT"; \
	docker rm -f agw >/dev/null 2>&1 || true; \
	docker run -d \
		--name agw \
		--network host \
		-e AGW_CONFIG="" \
		-e AGW_NETWORK_POLICY="" \
		-e AGW_ENABLE_K8S="true" \
		-e AGW_ENABLE_NXOS="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="$(AGW_VRF_MAP)" \
		-e AGW_DEBUG="true" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="$$AGW_TOKEN" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="true" \
		-e AGW_TIMESCAPE_PASSWORD="$(TIMESCAPE_PASSWORD)" \
		-e AGW_TIMESCAPE_ENDPOINT="https://$$KIND_NODE_IP:$$TIMESCAPE_NODEPORT/push" \
		-e AGW_PROMETHEUS_CLIENT_ENABLE="true" \
		-e AGW_PROMETHEUS_USERNAME="$(PROMETHEUS_USERNAME)" \
		-e AGW_PROMETHEUS_PASSWORD="$(PROMETHEUS_PASSWORD)" \
		-e AGW_PROMETHEUS_ENDPOINT="https://$$KIND_NODE_IP:30090/api/v1/write" \
		$(AGW_IMAGE); \
	echo "✅ AGW started (K8s + Prometheus + Timescape)"; \
	echo "  Prometheus: https://$$KIND_NODE_IP:30090/api/v1/write"; \
	echo "  Timescape:  https://$$KIND_NODE_IP:$$TIMESCAPE_NODEPORT/push"

# ============================================================================
# DPU Sim Targets
# ============================================================================

build-fwa-image:
	@echo "Building FWA test image: $(FWA_IMAGE)"
	@cd $(REPO_ROOT) && docker build -f Dockerfile.fwa -t $(FWA_IMAGE) --target=fwa-test .

pull-sim-image:
	@echo "Downloading DPU Sim tarball from GitHub releases: $(GITHUB_REPO)"
	@if command -v gh >/dev/null 2>&1; then \
		if [ "$(SIM_VERSION)" = "latest" ]; then \
			ACTUAL_VERSION=$$(gh release list --repo $(GITHUB_REPO) --limit 10 --exclude-drafts --json tagName --jq 'map(select(.tagName | startswith("dpu/") | not)) | .[0].tagName'); \
			if [ -z "$$ACTUAL_VERSION" ] || [ "$$ACTUAL_VERSION" = "null" ]; then \
				echo "❌ Could not determine latest published non-dpu release version"; \
				exit 1; \
			fi; \
			echo "🔍 Latest published release version: $$ACTUAL_VERSION"; \
		else \
			ACTUAL_VERSION=$(SIM_VERSION); \
		fi; \
		CLEAN_VERSION=$$(echo "$$ACTUAL_VERSION" | sed 's|^dpu/||' | sed 's/^v//'); \
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


# ============================================================================
# Container Lifecycle
# ============================================================================

create-ha-network:
	@docker network create --subnet=$(HA_SUBNET) $(HA_NETWORK) 2>/dev/null || echo "Network already exists"

remove-ha-network:
	@-docker network rm $(HA_NETWORK) 2>/dev/null || true

create-fwa-network:
	@docker network create --subnet=$(FWA_SUBNET) $(FWA_NETWORK) 2>/dev/null || echo "Network already exists"

remove-fwa-network:
	@-docker network rm $(FWA_NETWORK) 2>/dev/null || true

create-fwa-ha-network:
	@docker network create --subnet=$(FWA_SUBNET) $(FWA_HA_NETWORK) 2>/dev/null || echo "Network already exists"

remove-fwa-ha-network:
	@-docker network rm $(FWA_HA_NETWORK) 2>/dev/null || true

# HA containers run with NX-OS mock mode active and DPUs skipped
# (NX_AGENT_IGNORE_MODULES=1). Both nodes require 'Phase:' in show_status
# for ha/ tests to run.
launch-ha-agw: create-ha-network
	@echo "Starting HA AGW containers (DPU-less, NX-OS mock enabled)..."
	@-docker rm -f $(AGW_LEADER_NAME) $(AGW_FOLLOWER_NAME) >/dev/null 2>&1 || true
	@docker run -d --name $(AGW_LEADER_NAME) --network $(HA_NETWORK) --ip $(AGW_LEADER_IP) \
		-e AGW_ENABLE_NXOS="false" -e AGW_ENABLE_K8S="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="default:1,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003" \
		-e AGW_DEBUG="true" \
		-e AGW_HA_PEER_IP="$(AGW_FOLLOWER_IP)" -e AGW_HA_SOURCE_IP="$(AGW_LEADER_IP)" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="false" \
		-e NX_AGENT_IGNORE_MODULES="1" \
		$(AGW_IMAGE)
	@docker run -d --name $(AGW_FOLLOWER_NAME) --network $(HA_NETWORK) --ip $(AGW_FOLLOWER_IP) \
		-e AGW_ENABLE_NXOS="false" -e AGW_ENABLE_K8S="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="default:1,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003" \
		-e AGW_DEBUG="true" \
		-e AGW_HA_PEER_IP="$(AGW_LEADER_IP)" -e AGW_HA_SOURCE_IP="$(AGW_FOLLOWER_IP)" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="false" \
		-e NX_AGENT_IGNORE_MODULES="1" \
		$(AGW_IMAGE)
	@echo "HA AGW containers started (leader=$(AGW_LEADER_NAME) @ $(AGW_LEADER_IP), follower=$(AGW_FOLLOWER_NAME) @ $(AGW_FOLLOWER_IP))"

launch-fwa-agw: create-fwa-network
	@echo "Starting AGW for FWA on $(FWA_NETWORK)..."
	@-docker rm -f $(FWA_AGW_NAME) >/dev/null 2>&1 || true
	@docker run -d --name $(FWA_AGW_NAME) --network $(FWA_NETWORK) --ip $(FWA_AGW_IP) \
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
	@echo "AGW for FWA started at $(FWA_AGW_IP)"

launch-sim:
	@echo "Launching DPU Sim using original launch_sas.sh script"
	@# Kill any existing containers using DPU ports
	@-docker kill $$(docker ps -a -q --filter expose=11357-11363/tcp) >/dev/null 2>&1 || true
	@# Determine version: use SIM_VERSION if specified, otherwise pick newest tarball
	@if [ "$(SIM_VERSION)" != "latest" ]; then \
		ACTUAL_VER=$$(echo "$(SIM_VERSION)" | sed 's|^dpu/||' | sed 's/^v//'); \
		if [ ! -f "/tmp/naples-docker-$$ACTUAL_VER.tgz" ]; then \
			echo "❌ Tarball not found: /tmp/naples-docker-$$ACTUAL_VER.tgz"; \
			echo "Run 'make pull-sim-image SIM_VERSION=$(SIM_VERSION)' first"; \
			exit 1; \
		fi; \
	else \
		ACTUAL_VER=$$(ls -1 /tmp/naples-docker-*.tgz 2>/dev/null | sed 's|/tmp/naples-docker-||; s|.tgz$$||' | sort -V | tail -1); \
	fi; \
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

# ============================================================================
# Container Management Targets
# ============================================================================

shutdown-containers:
	@echo "Stopping containers and K8s infrastructure..."
	@-docker rm -f agw >/dev/null 2>&1 || true
	@-docker rm -f $(DSC_INSTANCE) >/dev/null 2>&1 || true
	@-kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || true
	@-rm -f $(KIND_KUBECONFIG) /tmp/$(KIND_CLUSTER_NAME)-agw-token /tmp/$(KIND_CLUSTER_NAME)-timescape-nodeport
	@echo "✅ All containers and kind cluster stopped"

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

launch-sim-multi:
	@echo "Launching $(SIM_COUNT) DPU Sim container(s) using launch_sas.sh"
	@-docker rm -f $$(docker ps -aq --filter "name=naples-") >/dev/null 2>&1 || true
	@# Determine version: use SIM_VERSION if specified, otherwise pick newest tarball
	@if [ "$(SIM_VERSION)" != "latest" ]; then \
		ACTUAL_VER=$$(echo "$(SIM_VERSION)" | sed 's|^dpu/||' | sed 's/^v//'); \
		if [ ! -f "/tmp/naples-docker-$$ACTUAL_VER.tgz" ]; then \
			echo "❌ Tarball not found: /tmp/naples-docker-$$ACTUAL_VER.tgz"; \
			echo "Run 'make pull-sim-image SIM_VERSION=$(SIM_VERSION)' first"; \
			exit 1; \
		fi; \
	else \
		ACTUAL_VER=$$(ls -1 /tmp/naples-docker-*.tgz 2>/dev/null | sed 's|/tmp/naples-docker-||; s|.tgz$$||' | sort -V | tail -1); \
	fi; \
	if [ -z "$$ACTUAL_VER" ]; then \
		echo "❌ No DPU Sim tarball found in /tmp/"; \
		echo "Run 'make pull-sim-image' first to download the tarball"; \
		exit 1; \
	fi; \
	SCRIPT_TARBALL="/tmp/naples-docker-$$ACTUAL_VER.tgz"; \
	if ! [ "$(SIM_COUNT)" -ge 1 ] 2>/dev/null; then \
		echo "❌ SIM_COUNT must be a positive integer"; \
		exit 1; \
	fi; \
	echo "Version: $$ACTUAL_VER"; \
	echo "Timeout: $(TIMEOUT)s"; \
	echo "SIM count: $(SIM_COUNT)"; \
	echo "📋 Using tarball: $$SCRIPT_TARBALL"; \
	chmod +x scripts/launch_sas.sh; \
	for IDX in $$(seq 1 $(SIM_COUNT)); do \
		INSTANCE_NAME="naples-$$ACTUAL_VER-$$IDX"; \
		if [ "$$IDX" -eq 1 ]; then \
			BIND_PORTS=""; \
		else \
			BIND_PORTS="1"; \
		fi; \
		SKIP_MOVE="0"; \
		UPLINK_PREFIX="sim$$IDX"; \
		DSC_IP_CIDR="192.168.$$((100 + IDX)).101/24"; \
		AGENT_IP_CIDR="169.254.201.$$IDX/32"; \
		echo "Launching $$INSTANCE_NAME (BIND_GRPC_PORTS=$${BIND_PORTS:-0}, UPLINK_PREFIX=$$UPLINK_PREFIX, DSC_HOST_IP=$$DSC_IP_CIDR, INT_MNIC0_IP=$$AGENT_IP_CIDR)"; \
		sudo NO_ADS=1 \
			DPUIMG="$$SCRIPT_TARBALL" \
			TIMEOUT=$(TIMEOUT) \
			VER="$$ACTUAL_VER" \
			DSC_INSTANCE="$$INSTANCE_NAME" \
			BIND_GRPC_PORTS="$$BIND_PORTS" \
			SKIP_UPLINK_MOVE="$$SKIP_MOVE" \
			UPLINK_PREFIX="$$UPLINK_PREFIX" \
			DSC_HOST_IP="$$DSC_IP_CIDR" \
			INT_MNIC0_IP="$$AGENT_IP_CIDR" \
			bash scripts/launch_sas.sh; \
		LAUNCH_EXIT=$$?; \
		if [ "$$LAUNCH_EXIT" -ne 0 ]; then \
			echo "❌ Failed to launch $$INSTANCE_NAME (exit: $$LAUNCH_EXIT)"; \
			exit $$LAUNCH_EXIT; \
		fi; \
	done; \
	sleep 3; \
	RUNNING_COUNT=$$(docker ps --filter "name=naples-$$ACTUAL_VER-" --format "{{.Names}}" | wc -l | tr -d ' '); \
	if [ "$$RUNNING_COUNT" -ge "$(SIM_COUNT)" ]; then \
		echo "✅ Launched $$RUNNING_COUNT DPU Sim container(s)"; \
		docker ps --filter "name=naples-$$ACTUAL_VER-" --format "  - {{.Names}}"; \
		echo "Host interfaces per SIM:"; \
		for IDX in $$(seq 1 $(SIM_COUNT)); do \
			echo "  - SIM $$IDX: sim$$IDX-eth1-1, sim$$IDX-eth1-2, sim$$IDX-dsc0 (IP 192.168.$$((100 + IDX)).101/24)"; \
		done; \
		exit 0; \
	else \
		echo "❌ Expected $(SIM_COUNT) DPU Sim container(s), found $$RUNNING_COUNT"; \
		docker ps -a | grep naples || echo "No naples containers found"; \
		exit 1; \
	fi

launch-fwa:
	@echo "Launching $(FWA_COUNT) FWA test container(s)..."
	@-docker rm -f $$(docker ps -aq --filter "name=$(FWA_CONTAINER_PREFIX)-") >/dev/null 2>&1 || true
	@if ! [ "$(FWA_COUNT)" -ge 1 ] 2>/dev/null; then \
		echo "❌ FWA_COUNT must be a positive integer"; \
		exit 1; \
	fi; \
	DPU_IP_ARRAY="$(FWA_DPU_IPS)"; \
	for IDX in $$(seq 1 $(FWA_COUNT)); do \
		INSTANCE_NAME="$(FWA_CONTAINER_PREFIX)-$$IDX"; \
		DPU_IP=$$(echo "$$DPU_IP_ARRAY" | awk "{print \$$$$IDX}"); \
		if [ -z "$$DPU_IP" ]; then \
			echo "❌ No DPU IP available for FWA $$IDX (only $$(echo $$DPU_IP_ARRAY | wc -w) IPs configured)"; \
			exit 1; \
		fi; \
		echo "Launching $$INSTANCE_NAME at $$DPU_IP"; \
		docker run -d \
			--name "$$INSTANCE_NAME" \
			--network $(FWA_NETWORK) --ip "$$DPU_IP" \
			--cap-add NET_ADMIN \
			-e FWA_CONFIG="" \
			-e FWA_NETWORK_POLICY="" \
			-e FWA_ENABLE_DATAPLANE="false" \
			-e FWA_ENABLE_AGW="true" \
			-e FWA_ENABLE_LOGGER="false" \
			-e FWA_SERVER_ADDRESS="$(FWA_AGW_IP):8880" \
			-e FWA_DP_SOCKET_PATH="" \
			-e FWA_DEBUG="true" \
			$(FWA_IMAGE); \
		if [ $$? -ne 0 ]; then \
			echo "❌ Failed to launch $$INSTANCE_NAME"; \
			exit 1; \
		fi; \
	done; \
	sleep 2; \
	RUNNING_COUNT=$$(docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "{{.Names}}" | wc -l | tr -d ' '); \
	if [ "$$RUNNING_COUNT" -ge "$(FWA_COUNT)" ]; then \
		echo "✅ Launched $$RUNNING_COUNT FWA test container(s)"; \
		docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "  - {{.Names}} @ {{.Networks}}"; \
	else \
		echo "❌ Expected $(FWA_COUNT) FWA container(s), found $$RUNNING_COUNT"; \
		docker ps -a --filter "name=$(FWA_CONTAINER_PREFIX)-" || echo "No FWA containers found"; \
		exit 1; \
	fi

launch-containers: build-agw-image pull-sim-image launch-sim launch-agw configure-network status
	@echo "Stack ready"

launch-containers-multi: build-agw-image pull-sim-image launch-sim-multi launch-agw configure-network-multi status
	@echo "Multi-SIM stack ready"

seed-fwa-gnmi:
	@echo "Seeding mock gNMI with DPU inventory..."
	@echo "Waiting for AGW CLI server to be ready..."
	@for i in $$(seq 1 15); do \
		docker exec $(FWA_AGW_NAME) ./agwctl health >/dev/null 2>&1 && break; \
		sleep 1; \
	done
	@docker cp testdata/gnmi/default_gnmi.json $(FWA_AGW_NAME):/tmp/mock_gnmi_seed.json
	@docker exec $(FWA_AGW_NAME) ./agwctl mock gnmi set --file /tmp/mock_gnmi_seed.json >/dev/null 2>&1
	@echo "Waiting for gNMI notifications to propagate..."
	@sleep 3
	@PHASE=$$(docker exec $(FWA_AGW_NAME) ./agwctl show_status 2>&1 | grep "Phase:" | awk '{print $$2}'); \
	if [ -z "$$PHASE" ]; then \
		echo "  ❌ AGW has no Phase (NX-OS mock may not be active)"; \
	elif echo "$$PHASE" | grep -qE "dpu-ready|redir-done|running"; then \
		echo "  ✅ AGW phase: $$PHASE (DPU listener ready)"; \
	else \
		echo "  ⏳ AGW phase: $$PHASE (may still be initializing)"; \
	fi

seed-fwa-ha-gnmi:
	@echo "Seeding mock gNMI on HA AGW containers..."
	@echo "Waiting for AGW CLI servers to be ready..."
	@for C in $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME); do \
		for i in $$(seq 1 15); do \
			docker exec $$C ./agwctl health >/dev/null 2>&1 && break; \
			sleep 1; \
		done; \
	done
	@for C in $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME); do \
		echo "  Seeding $$C with DPU inventory..."; \
		docker cp testdata/gnmi/default_gnmi.json $$C:/tmp/mock_gnmi_seed.json; \
		docker exec $$C ./agwctl mock gnmi set --file /tmp/mock_gnmi_seed.json >/dev/null 2>&1; \
	done
	@echo "Waiting for DPU inventory to propagate..."
	@sleep 3
	@# Enable HA on each AGW (mirrors ha/conftest.py _seed_gnmi_and_enable_ha)
	@# Order matters: set source IP first, then enable HA, then add peer.
	@# If peer is added before source IP, the HA manager activates with empty localIP.
	@echo "Configuring HA on leader..."
	@docker exec $(FWA_HA_AGW_LEADER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr" \
		--value $(FWA_HA_AGW_LEADER_IP) >/dev/null 2>&1
	@docker exec $(FWA_HA_AGW_LEADER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState" \
		--value enabled >/dev/null 2>&1
	@docker exec $(FWA_HA_AGW_LEADER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=$(FWA_HA_AGW_FOLLOWER_IP)]" \
		--value '{"ipAddr":"$(FWA_HA_AGW_FOLLOWER_IP)"}' >/dev/null 2>&1
	@echo "Configuring HA on follower..."
	@docker exec $(FWA_HA_AGW_FOLLOWER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/state-items/agent-items/SasAgent-list[svcName=hypershield]/agentHaSrcIntfAddr" \
		--value $(FWA_HA_AGW_FOLLOWER_IP) >/dev/null 2>&1
	@docker exec $(FWA_HA_AGW_FOLLOWER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/adminState" \
		--value enabled >/dev/null 2>&1
	@docker exec $(FWA_HA_AGW_FOLLOWER_NAME) ./agwctl mock gnmi set \
		--path "device:/System/sas-items/svc-items/svcinst-items/SvcInstance-list[name=hypershield]/ha-items/peer-items/HaPeer-list[ipAddr=$(FWA_HA_AGW_LEADER_IP)]" \
		--value '{"ipAddr":"$(FWA_HA_AGW_LEADER_IP)"}' >/dev/null 2>&1
	@echo "Waiting for HA config to propagate..."
	@sleep 3
	@for C in $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME); do \
		PHASE=$$(docker exec $$C ./agwctl show_status 2>&1 | grep "Phase:" | awk '{print $$2}'); \
		HAS_HA=$$(docker exec $$C ./agwctl config show 2>&1 | grep -c "CONFIG_TYPE_HA" || true); \
		if [ "$$HAS_HA" -gt 0 ]; then \
			echo "  ✅ $$C: phase=$${PHASE:-unknown}, HA config present"; \
		else \
			echo "  ⏳ $$C: phase=$${PHASE:-unknown}, HA config not yet available"; \
		fi; \
	done

launch-containers-fwa: build-agw-image build-fwa-image launch-fwa-agw seed-fwa-gnmi launch-fwa configure-fwa-network status
	@echo "FWA stack ready"

launch-fwa-ha-agw: create-fwa-ha-network
	@echo "Starting HA AGW containers for FWA on $(FWA_HA_NETWORK)..."
	@-docker rm -f $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME) >/dev/null 2>&1 || true
	@docker run -d --name $(FWA_HA_AGW_LEADER_NAME) --network $(FWA_HA_NETWORK) --ip $(FWA_HA_AGW_LEADER_IP) \
		-e AGW_ENABLE_NXOS="false" -e AGW_ENABLE_K8S="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="default:1,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003" \
		-e AGW_DEBUG="true" \
		-e AGW_HA_PEER_IP="$(FWA_HA_AGW_FOLLOWER_IP)" -e AGW_HA_SOURCE_IP="$(FWA_HA_AGW_LEADER_IP)" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="false" \
		$(AGW_IMAGE)
	@docker run -d --name $(FWA_HA_AGW_FOLLOWER_NAME) --network $(FWA_HA_NETWORK) --ip $(FWA_HA_AGW_FOLLOWER_IP) \
		-e AGW_ENABLE_NXOS="false" -e AGW_ENABLE_K8S="false" \
		-e AGW_DPU_SERVER_ADDRESS="0.0.0.0:8880" \
		-e AGW_VRF_MAP="default:1,epbr-1001:1001,epbr-1002:1002,epbr-1003:1003" \
		-e AGW_DEBUG="true" \
		-e AGW_HA_PEER_IP="$(FWA_HA_AGW_LEADER_IP)" -e AGW_HA_SOURCE_IP="$(FWA_HA_AGW_FOLLOWER_IP)" \
		-e AGW_K8S_SERVICE_ACCOUNT_AUTH="" \
		-e AGW_TIMESCAPE_CLIENT_ENABLE="false" \
		$(AGW_IMAGE)
	@echo "HA AGW for FWA started (leader=$(FWA_HA_AGW_LEADER_NAME) @ $(FWA_HA_AGW_LEADER_IP), follower=$(FWA_HA_AGW_FOLLOWER_NAME) @ $(FWA_HA_AGW_FOLLOWER_IP))"

launch-fwa-ha:
	@echo "Launching $(FWA_COUNT) FWA test container(s) for HA..."
	@-docker rm -f $$(docker ps -aq --filter "name=$(FWA_CONTAINER_PREFIX)-") >/dev/null 2>&1 || true
	@if ! [ "$(FWA_COUNT)" -ge 1 ] 2>/dev/null; then \
		echo "❌ FWA_COUNT must be a positive integer"; \
		exit 1; \
	fi; \
	DPU_IP_ARRAY="$(FWA_DPU_IPS)"; \
	for IDX in $$(seq 1 $(FWA_COUNT)); do \
		INSTANCE_NAME="$(FWA_CONTAINER_PREFIX)-$$IDX"; \
		DPU_IP=$$(echo "$$DPU_IP_ARRAY" | awk "{print \$$$$IDX}"); \
		if [ -z "$$DPU_IP" ]; then \
			echo "❌ No DPU IP available for FWA $$IDX (only $$(echo $$DPU_IP_ARRAY | wc -w) IPs configured)"; \
			exit 1; \
		fi; \
		echo "Launching $$INSTANCE_NAME at $$DPU_IP"; \
		docker run -d \
			--name "$$INSTANCE_NAME" \
			--network $(FWA_HA_NETWORK) --ip "$$DPU_IP" \
			--cap-add NET_ADMIN \
			-e FWA_CONFIG="" \
			-e FWA_NETWORK_POLICY="" \
			-e FWA_ENABLE_DATAPLANE="false" \
			-e FWA_ENABLE_AGW="true" \
			-e FWA_ENABLE_LOGGER="false" \
			-e FWA_SERVER_ADDRESS="$(FWA_HA_AGW_LEADER_IP):8880" \
			-e FWA_DP_SOCKET_PATH="" \
			-e FWA_DEBUG="true" \
			$(FWA_IMAGE); \
		if [ $$? -ne 0 ]; then \
			echo "❌ Failed to launch $$INSTANCE_NAME"; \
			exit 1; \
		fi; \
	done; \
	sleep 2; \
	RUNNING_COUNT=$$(docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "{{.Names}}" | wc -l | tr -d ' '); \
	if [ "$$RUNNING_COUNT" -ge "$(FWA_COUNT)" ]; then \
		echo "✅ Launched $$RUNNING_COUNT FWA test container(s) for HA"; \
		docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "  - {{.Names}} @ {{.Networks}}"; \
	else \
		echo "❌ Expected $(FWA_COUNT) FWA container(s), found $$RUNNING_COUNT"; \
		docker ps -a --filter "name=$(FWA_CONTAINER_PREFIX)-" || echo "No FWA containers found"; \
		exit 1; \
	fi

launch-containers-fwa-ha: build-agw-image build-fwa-image launch-fwa-ha-agw seed-fwa-ha-gnmi launch-fwa-ha configure-fwa-ha-network status
	@echo "FWA HA stack ready"

# ============================================================================
# Network Configuration (FWA)
# ============================================================================

configure-fwa-network:
	@echo "Configuring FWA container int_mnic0 interfaces..."
	@FWA_CONTAINERS="$$(docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "{{.Names}}")"; \
	if [ -z "$$FWA_CONTAINERS" ]; then \
		echo "❌ No running FWA containers found"; \
		exit 1; \
	fi; \
	for C in $$FWA_CONTAINERS; do \
		CONTAINER_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$C"); \
		if [ -z "$$CONTAINER_IP" ]; then \
			echo "  ❌ $$C: could not determine IP address"; \
			continue; \
		fi; \
		echo "  - $$C: setting up int_mnic0 with $$CONTAINER_IP"; \
		docker exec "$$C" sh -c "ip link show int_mnic0 >/dev/null 2>&1 || ip link add int_mnic0 type dummy" >/dev/null 2>&1; \
		docker exec "$$C" sh -c "ip addr add $$CONTAINER_IP/32 dev int_mnic0 2>/dev/null || true" >/dev/null 2>&1; \
		docker exec "$$C" sh -c "ip link set int_mnic0 up" >/dev/null 2>&1; \
		VERIFY_IP=$$(docker exec "$$C" sh -c "ip -4 -o addr show dev int_mnic0 2>/dev/null | awk '{print \$$4}' | cut -d/ -f1"); \
		if [ "$$VERIFY_IP" = "$$CONTAINER_IP" ]; then \
			echo "    ✅ int_mnic0=$$CONTAINER_IP"; \
		else \
			echo "    ❌ verification failed (expected $$CONTAINER_IP, got $$VERIFY_IP)"; \
		fi; \
	done

configure-fwa-ha-network:
	@echo "Configuring FWA HA container int_mnic0 interfaces..."
	@FWA_CONTAINERS="$$(docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "{{.Names}}")"; \
	if [ -z "$$FWA_CONTAINERS" ]; then \
		echo "❌ No running FWA containers found"; \
		exit 1; \
	fi; \
	for C in $$FWA_CONTAINERS; do \
		CONTAINER_IP=$$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$$C"); \
		if [ -z "$$CONTAINER_IP" ]; then \
			echo "  ❌ $$C: could not determine IP address"; \
			continue; \
		fi; \
		echo "  - $$C: setting up int_mnic0 with $$CONTAINER_IP"; \
		docker exec "$$C" sh -c "ip link show int_mnic0 >/dev/null 2>&1 || ip link add int_mnic0 type dummy" >/dev/null 2>&1; \
		docker exec "$$C" sh -c "ip addr add $$CONTAINER_IP/32 dev int_mnic0 2>/dev/null || true" >/dev/null 2>&1; \
		docker exec "$$C" sh -c "ip link set int_mnic0 up" >/dev/null 2>&1; \
		VERIFY_IP=$$(docker exec "$$C" sh -c "ip -4 -o addr show dev int_mnic0 2>/dev/null | awk '{print \$$4}' | cut -d/ -f1"); \
		if [ "$$VERIFY_IP" = "$$CONTAINER_IP" ]; then \
			echo "    ✅ int_mnic0=$$CONTAINER_IP"; \
		else \
			echo "    ❌ verification failed (expected $$CONTAINER_IP, got $$VERIFY_IP)"; \
		fi; \
	done

# ============================================================================
# Status & Shutdown (handle any combination of running containers)
# ============================================================================

status:
	@echo "Container Status:"
	@docker ps --filter "name=agw" --filter "name=naples-" --filter "name=$(FWA_CONTAINER_PREFIX)" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "No containers running"
	@echo ""
	@echo "Health Checks:"
	@for C in agw $(AGW_LEADER_NAME) $(AGW_FOLLOWER_NAME) $(FWA_AGW_NAME) $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME); do \
		if docker ps --filter "name=$$C" --format "{{.Names}}" | grep -qx "$$C"; then \
			docker exec $$C ./agwctl health >/dev/null 2>&1 \
				&& echo "  ✅ $$C: healthy" \
				|| echo "  ❌ $$C: unhealthy"; \
		fi; \
	done
	@DPU_CONTAINERS="$$(docker ps --filter "name=naples-" --format "{{.Names}}")"; \
	if [ -n "$$DPU_CONTAINERS" ]; then \
		for C in $$DPU_CONTAINERS; do \
			docker exec "$$C" pgrep -f "pds_dp_app" >/dev/null 2>&1 \
				&& echo "  ✅ $$C: dataplane running" \
				|| echo "  ❌ $$C: dataplane not running"; \
		done; \
	fi
	@FWA_CONTAINERS="$$(docker ps --filter "name=$(FWA_CONTAINER_PREFIX)-" --format "{{.Names}}")"; \
	if [ -n "$$FWA_CONTAINERS" ]; then \
		for C in $$FWA_CONTAINERS; do \
			docker exec "$$C" pgrep -f "fwa" >/dev/null 2>&1 \
				&& echo "  ✅ $$C: FWA process running" \
				|| echo "  ❌ $$C: FWA process not running"; \
		done; \
	fi

shutdown:
	@echo "Stopping all containers..."
	@# Single AGW and HA containers
	@for C in agw $(AGW_LEADER_NAME) $(AGW_FOLLOWER_NAME) $(FWA_AGW_NAME) $(FWA_HA_AGW_LEADER_NAME) $(FWA_HA_AGW_FOLLOWER_NAME); do \
		if docker ps -a --filter "name=$$C" --format "{{.Names}}" | grep -qx "$$C"; then \
			echo "  Removing $$C"; \
			docker rm -f $$C >/dev/null 2>&1 || true; \
		fi; \
	done
	@# DPU Sim containers (single and multi)
	@SIM_CONTAINERS="$$(docker ps -a --filter "name=naples-" --format "{{.Names}}")"; \
	if [ -n "$$SIM_CONTAINERS" ]; then \
		echo "  Removing DPU Sim containers: $$SIM_CONTAINERS"; \
		docker rm -f $$SIM_CONTAINERS >/dev/null 2>&1 || true; \
	fi
	@# FWA test containers (single and multi)
	@FWA_CONTAINERS="$$(docker ps -a --filter "name=$(FWA_CONTAINER_PREFIX)" --format "{{.Names}}")"; \
	if [ -n "$$FWA_CONTAINERS" ]; then \
		echo "  Removing FWA test containers: $$FWA_CONTAINERS"; \
		docker rm -f $$FWA_CONTAINERS >/dev/null 2>&1 || true; \
	fi
	@# Clean up host SIM interfaces
	@for IFACE in $$(ip -o link show 2>/dev/null | awk -F': ' '{print $$2}' | sed 's/@.*//' | grep -E '^sim[0-9]+-(eth1-1|eth1-2|dsc0)$$' || true); do \
		echo "  Deleting interface $$IFACE"; \
		sudo ip link delete "$$IFACE" >/dev/null 2>&1 || true; \
	done
	@# Remove networks if they exist
	@for NET in $(HA_NETWORK) $(FWA_NETWORK) $(FWA_HA_NETWORK); do \
		if docker network ls --format "{{.Name}}" | grep -q "^$$NET$$"; then \
			echo "  Removing network $$NET"; \
			docker network rm $$NET >/dev/null 2>&1 || true; \
		fi; \
	done
	@echo "✅ Shutdown complete"


# ============================================================================
# Network Configuration
# ============================================================================

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

configure-network-multi:
	@echo "Configuring host IP alias $(HOST_AGW_IP) (Ubuntu)"
	@sh -c 'if ! ip addr show lo | grep -q "$(HOST_AGW_IP)"; then sudo ip addr add $(HOST_AGW_IP)/32 dev lo; else echo "IP already configured"; fi'
	@DPU_CONTAINERS="$$(docker ps --filter "name=naples-" --format "{{.Names}}")"; \
	if [ -z "$$DPU_CONTAINERS" ]; then \
		echo "❌ No running DPU Sim containers found"; \
		exit 1; \
	fi; \
	if [ "$(APPLY_ROUTE)" = "1" ]; then \
		echo "Configuring DPU route to AGW IP via Docker bridge"; \
		BRIDGE_IP=$$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'); \
		for C in $$DPU_CONTAINERS; do \
			echo "  - $$C: route $(HOST_AGW_IP) via $$BRIDGE_IP"; \
			docker exec "$$C" ip route add $(HOST_AGW_IP) via $$BRIDGE_IP 2>/dev/null || echo "    Route already exists"; \
		done; \
	else \
		echo "Skipping DPU bridge route (APPLY_ROUTE=0)"; \
	fi; \
	echo "Creating DPU mgmt alias int_mnic0 to satisfy FWA (idempotent)"; \
	for C in $$DPU_CONTAINERS; do \
		SUFFIX=$$(echo "$$C" | sed -n 's/.*-\([0-9][0-9]*\)$$/\1/p'); \
		if [ -z "$$SUFFIX" ]; then \
			echo "  - $$C: unable to parse index, skipping int_mnic0 remap"; \
			continue; \
		fi; \
		AGENT_IP="169.254.201.$$SUFFIX/32"; \
		echo "  - $$C: ensuring int_mnic0=$$AGENT_IP"; \
		docker exec "$$C" sh -c 'ip link show int_mnic0 >/dev/null 2>&1 || ip link add int_mnic0 type dummy'; \
		CURRENT_IP=$$(docker exec "$$C" sh -c "ip -4 -o addr show dev int_mnic0 2>/dev/null | awk '{print \$$4}' | head -1"); \
		if [ "$$CURRENT_IP" != "$$AGENT_IP" ]; then \
			echo "    updating int_mnic0 from '$$CURRENT_IP' to '$$AGENT_IP'"; \
			docker exec "$$C" sh -c 'ip addr flush dev int_mnic0'; \
			docker exec "$$C" sh -c "ip addr add $$AGENT_IP dev int_mnic0"; \
		fi; \
		docker exec "$$C" sh -c 'ip link set int_mnic0 up || true'; \
	done

show-containers-status-multi:
	@echo "Container Status:"
	@docker ps --filter "name=agw" --filter "name=naples-" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "No containers running"
	@echo ""
	@echo "Health Checks:"
	@if docker ps --filter "name=agw" --format "{{.Names}}" | grep -q agw; then \
		docker exec agw ./agwctl health >/dev/null 2>&1 && echo "✅ AGW is healthy" || echo "❌ AGW health check failed"; \
	else \
		echo "❌ AGW not running"; \
	fi
	@DPU_CONTAINERS="$$(docker ps --filter "name=naples-" --format "{{.Names}}")"; \
	if [ -n "$$DPU_CONTAINERS" ]; then \
		for C in $$DPU_CONTAINERS; do \
			docker exec "$$C" pgrep -f "pds_dp_app" >/dev/null 2>&1 && echo "✅ $$C dataplane is running" || echo "❌ $$C dataplane not running"; \
		done; \
	else \
		echo "❌ DPU not running"; \
	fi

shutdown-containers-multi:
	@echo "Stopping containers and K8s infrastructure..."
	@-docker rm -f agw >/dev/null 2>&1 || true
	@-docker rm -f $$(docker ps -aq --filter "name=naples-") >/dev/null 2>&1 || true
	@-kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || true
	@-rm -f $(KIND_KUBECONFIG) /tmp/$(KIND_CLUSTER_NAME)-agw-token /tmp/$(KIND_CLUSTER_NAME)-timescape-nodeport
	@echo "Cleaning host SIM interfaces..."
	@for IFACE in $$(ip -o link show | awk -F': ' '{print $$2}' | sed 's/@.*//' | grep -E '^sim[0-9]+-(eth1-1|eth1-2|dsc0)$$' || true); do \
		echo "  - deleting $$IFACE"; \
		sudo ip link delete "$$IFACE" >/dev/null 2>&1 || true; \
	done
	@echo "✅ All containers and kind cluster stopped"

# ============================================================================
# K8s Infrastructure Targets (prerequisites of launch-agw)
# ============================================================================
# These targets are called automatically by launch-agw to set up a local kind
# cluster with Prometheus, Timescape, CRDs, and a ServiceAccount. They can also
# be invoked individually for debugging or incremental setup.
#
# Prerequisites: kind (https://kind.sigs.k8s.io/), kubectl

create-kind-cluster:
	@command -v kind >/dev/null 2>&1 || { echo "❌ 'kind' not found. Install: https://kind.sigs.k8s.io/docs/user/quick-start/#installation"; exit 1; }
	@command -v kubectl >/dev/null 2>&1 || { echo "❌ 'kubectl' not found. Install: https://kubernetes.io/docs/tasks/tools/"; exit 1; }
	@echo "Creating kind cluster: $(KIND_CLUSTER_NAME)..."
	@if kind get clusters 2>/dev/null | grep -q "^$(KIND_CLUSTER_NAME)$$"; then \
		echo "✅ Kind cluster '$(KIND_CLUSTER_NAME)' already exists"; \
	else \
		kind create cluster --name $(KIND_CLUSTER_NAME) --kubeconfig $(KIND_KUBECONFIG) --wait 60s; \
		echo "✅ Kind cluster '$(KIND_CLUSTER_NAME)' created"; \
	fi
	@echo "Kubeconfig: $(KIND_KUBECONFIG)"

deploy-crds:
	@echo "Deploying SmartSwitchNetworkPolicy CRD to kind cluster..."
	@if [ ! -f "$(CRD_PATH)" ]; then \
		echo "❌ CRD file not found: $(CRD_PATH)"; \
		exit 1; \
	fi
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f $(CRD_PATH)
	@echo "✅ CRD deployed"

deploy-prometheus:
	@echo "Deploying Prometheus with remote-write receiver..."
	@# Resolve kind node IP for TLS SAN
	@KIND_NODE_IP=$$(docker inspect $(KIND_CLUSTER_NAME)-control-plane -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo '127.0.0.1'); \
	echo "Kind node IP: $$KIND_NODE_IP"; \
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f $(K8S_MANIFESTS_DIR)/prometheus.yaml || true; \
	echo "Generating Prometheus basic auth secret..."; \
	BCRYPT_HASH=$$(htpasswd -nbBC 10 "" "$(PROMETHEUS_PASSWORD)" | tr -d ':\n' | sed 's/^\$$2y/\$$2y/'); \
	printf 'basic_auth_users:\n  $(PROMETHEUS_USERNAME): "%s"\ntls_server_config:\n  cert_file: /etc/prometheus/tls/tls.crt\n  key_file: /etc/prometheus/tls/tls.key\n' "$$BCRYPT_HASH" > /tmp/prometheus-web.yml; \
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl -n monitoring create secret generic prometheus-auth \
		--from-file=web.yml=/tmp/prometheus-web.yml --dry-run=client -o yaml | \
		KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f -; \
	rm -f /tmp/prometheus-web.yml; \
	echo "Generating self-signed TLS certificate for Prometheus..."; \
	openssl req -x509 -newkey rsa:2048 -keyout /tmp/prometheus-tls.key -out /tmp/prometheus-tls.crt \
		-days 365 -nodes -subj '/CN=prometheus.monitoring.svc' \
		-addext "subjectAltName=DNS:prometheus,DNS:prometheus.monitoring.svc,IP:127.0.0.1,IP:$$KIND_NODE_IP" 2>/dev/null; \
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl -n monitoring delete secret prometheus-tls 2>/dev/null || true; \
	KUBECONFIG=$(KIND_KUBECONFIG) kubectl -n monitoring create secret tls prometheus-tls \
		--cert=/tmp/prometheus-tls.crt --key=/tmp/prometheus-tls.key; \
	rm -f /tmp/prometheus-tls.key /tmp/prometheus-tls.crt
	@# Restart deployment to pick up TLS secret
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl rollout restart deployment/prometheus -n monitoring 2>/dev/null || true
	@echo "Waiting for Prometheus to be ready..."
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl rollout status deployment/prometheus -n monitoring --timeout=120s
	@echo "✅ Prometheus deployed (NodePort 30090, HTTPS)"

deploy-timescape:
	@command -v helm >/dev/null 2>&1 || { echo "❌ 'helm' not found. Install: https://helm.sh/docs/intro/install/"; exit 1; }
	@echo "Deploying Hubble Timescape ($(TIMESCAPE_CHART_VERSION))..."
	@# Create namespace and push API password secret
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl create namespace hubble-timescape --dry-run=client -o yaml | \
		KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f -
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl -n hubble-timescape create secret generic hubble-timescape-push-api-password \
		--from-literal "PUSH_API_PASSWORD=$(TIMESCAPE_PASSWORD)" --dry-run=client -o yaml | \
		KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f -
	@# Pull and install the Helm chart
	@CHART_FILE="/tmp/hubble-timescape-$(TIMESCAPE_CHART_VERSION).tgz"; \
	if [ ! -f "$$CHART_FILE" ]; then \
		echo "Pulling Timescape chart..."; \
		helm pull $(TIMESCAPE_CHART_OCI) --version $(TIMESCAPE_CHART_VERSION) --destination /tmp/; \
	else \
		echo "Using cached chart: $$CHART_FILE"; \
	fi; \
	echo "Installing Hubble Timescape via Helm..."; \
	KUBECONFIG=$(KIND_KUBECONFIG) helm upgrade --install hubble-timescape "$$CHART_FILE" \
		--namespace hubble-timescape \
		--values $(TIMESCAPE_VALUES) \
		--timeout 300s \
		--wait
	@echo "Waiting for Timescape pods to be ready..."
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl wait --for=condition=ready pod -l app.kubernetes.io/part-of=hubble-timescape -n hubble-timescape --timeout=300s 2>/dev/null || \
		KUBECONFIG=$(KIND_KUBECONFIG) kubectl get pods -n hubble-timescape
	@# Detect the ingester NodePort and patch the client ConfigMap
	@KIND_NODE_IP=$$(docker inspect $(KIND_CLUSTER_NAME)-control-plane -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo '127.0.0.1'); \
	TIMESCAPE_NODEPORT=$$(kubectl --kubeconfig $(KIND_KUBECONFIG) -n hubble-timescape get svc hubble-timescape-ingester -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo ''); \
	if [ -z "$$TIMESCAPE_NODEPORT" ]; then \
		echo "⚠️  Could not detect Timescape NodePort, using default 30869"; \
		TIMESCAPE_NODEPORT=30869; \
	fi; \
	echo "Timescape endpoint: https://$$KIND_NODE_IP:$$TIMESCAPE_NODEPORT/push"; \
	echo "Deploying client ConfigMap (smartswitch-timescape-config)..."; \
	sed "s/PLACEHOLDER_HOST/$$KIND_NODE_IP/g; s/PLACEHOLDER_PORT/$$TIMESCAPE_NODEPORT/g; s/PLACEHOLDER_PASSWORD/$(TIMESCAPE_PASSWORD)/g" \
		$(K8S_MANIFESTS_DIR)/timescape.yaml | KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f -; \
	echo "$$TIMESCAPE_NODEPORT" > /tmp/$(KIND_CLUSTER_NAME)-timescape-nodeport
	@echo "✅ Hubble Timescape deployed"

generate-sa-token:
	@echo "Creating ServiceAccount '$(K8S_SA_NAME)' in namespace '$(K8S_NAMESPACE)'..."
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl create serviceaccount $(K8S_SA_NAME) -n $(K8S_NAMESPACE) 2>/dev/null || \
		echo "ServiceAccount already exists"
	@echo "Creating ClusterRoleBinding for ServiceAccount..."
	@KUBECONFIG=$(KIND_KUBECONFIG) kubectl create clusterrolebinding $(K8S_SA_NAME)-admin \
		--clusterrole=cluster-admin \
		--serviceaccount=$(K8S_NAMESPACE):$(K8S_SA_NAME) 2>/dev/null || \
		echo "ClusterRoleBinding already exists"
	@echo "Generating long-lived SA token..."
	@printf 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: $(K8S_SA_NAME)-token\n  namespace: $(K8S_NAMESPACE)\n  annotations:\n    kubernetes.io/service-account.name: $(K8S_SA_NAME)\ntype: kubernetes.io/service-account-token\n' \
		| KUBECONFIG=$(KIND_KUBECONFIG) kubectl apply -f -
	@echo "Waiting for token to be populated..."
	@sleep 3
	@# Extract API server URL, token, and CA cert; encode as AGW-format base64 token
	@API_SERVER=$$(KUBECONFIG=$(KIND_KUBECONFIG) kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'); \
	SA_TOKEN=$$(KUBECONFIG=$(KIND_KUBECONFIG) kubectl get secret $(K8S_SA_NAME)-token -n $(K8S_NAMESPACE) -o jsonpath='{.data.token}' | base64 -d); \
	CA_CERT=$$(KUBECONFIG=$(KIND_KUBECONFIG) kubectl get secret $(K8S_SA_NAME)-token -n $(K8S_NAMESPACE) -o jsonpath='{.data.ca\.crt}' | base64 -d); \
	AGW_TOKEN=$$(printf '%s|%s|%s' "$$API_SERVER" "$$SA_TOKEN" "$$CA_CERT" | base64 | tr -d '\n'); \
	echo ""; \
	echo "API Server: $$API_SERVER"; \
	echo "AGW Token (first 80 chars): $$(echo $$AGW_TOKEN | cut -c1-80)..."; \
	echo ""; \
	echo "✅ SA token generated. Use with:"; \
	echo "  make launch-agw AGW_SA_TOKEN=$$AGW_TOKEN"; \
	echo ""; \
	echo "$$AGW_TOKEN" > /tmp/$(KIND_CLUSTER_NAME)-agw-token; \
	echo "Token saved to: /tmp/$(KIND_CLUSTER_NAME)-agw-token"

teardown-kind-cluster:
	@echo "Deleting kind cluster: $(KIND_CLUSTER_NAME)..."
	@kind delete cluster --name $(KIND_CLUSTER_NAME) 2>/dev/null || true
	@rm -f $(KIND_KUBECONFIG) /tmp/$(KIND_CLUSTER_NAME)-agw-token /tmp/$(KIND_CLUSTER_NAME)-timescape-nodeport
	@echo "✅ Kind cluster deleted"

# ============================================================================
# HA Targets (leader = lowest IP, wins election per ha/manager.go)
# ============================================================================

shutdown-ha-containers:
	@-docker rm -f $(AGW_LEADER_NAME) $(AGW_FOLLOWER_NAME) >/dev/null 2>&1 || true
	@$(MAKE) remove-ha-network
	@echo "HA containers stopped"

show-ha-status:
	@docker ps --filter "name=$(AGW_LEADER_NAME)" --filter "name=$(AGW_FOLLOWER_NAME)" \
		--format "table {{.Names}}\t{{.Status}}" || echo "No HA containers"
	@for c in $(AGW_LEADER_NAME) $(AGW_FOLLOWER_NAME); do \
		if docker ps --filter "name=$$c" --format "{{.Names}}" | grep -q "$$c"; then \
			docker exec $$c ./agwctl health >/dev/null 2>&1 && echo "  $$c: healthy" || echo "  $$c: unhealthy"; \
		else echo "  $$c: not running"; fi; done

attach-agw:
	@echo "Attaching to AGW container: agw"
	@docker exec -it agw sh

attach-sim:
	@echo "Attaching to DPU Sim container: $(DSC_INSTANCE)"
	@docker exec -it $(DSC_INSTANCE) bash

attach-fwa:
	@echo "Attaching to FWA test container: $(FWA_CONTAINER_PREFIX)-1"
	@docker exec -it $(FWA_CONTAINER_PREFIX)-1 sh


# ============================================================================
# Tests
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

run-nxos-tests:
	$(PYTEST) -v nxos/

run-ha-tests:
	AGW_CONTAINER=$(AGW_LEADER_NAME) AGW_LEADER=$(AGW_LEADER_NAME) AGW_FOLLOWER=$(AGW_FOLLOWER_NAME) \
	$(PYTEST) -v -m ha ha/

run-tests-with-allure:
	$(PYTEST) -v --alluredir=allure-results

show-allure-report:
	allure serve allure-results

run-specific-test:
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make run-specific-test TEST=test_policy.py::test_agw_health"; \
	else \
		$(PYTEST) -v $(TEST); \
	fi


# ============================================================================
# Utility
# ============================================================================

clean-test-artifacts:
	rm -rf $(VENV)
	rm -rf allure-results
	rm -rf .pytest_cache
	rm -rf __pycache__
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
