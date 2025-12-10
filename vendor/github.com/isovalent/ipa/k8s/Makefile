include $(CURDIR)/../Makefile.defs

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: vendor
vendor:
	$(MAKE) tidy
	$(GO) mod vendor
	$(GO) mod verify

.PHONY: k8s
k8s:
	$(GO) tool controller-gen crd paths="./apis/isovalent.com/v1alpha1" output:dir=crds/isovalent.com/v1alpha1
	$(GO) tool controller-gen object paths="./apis/isovalent.com/v1alpha1"
	$(GO) tool controller-gen crd paths="./apis/cilium.io/v1alpha1" output:dir=crds/cilium.io/v1alpha1
	$(GO) tool controller-gen object paths="./apis/cilium.io/v1alpha1"

.PHONY: lint
lint:
	$(GO) install sigs.k8s.io/kube-api-linter/cmd/golangci-lint-kube-api-linter@$(KUBE_API_LINTER_VERSION)
	golangci-lint-kube-api-linter run ./apis/isovalent.com/v1alpha1 --fix

.PHONY: test-crd-validation
test-crd-validation:
	@echo "Running CRD validation tests against Kubernetes API server..."
	@apis/isovalent.com/v1alpha1/testdata/run-validation-tests.sh
