# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# Update this via images/scripts/update-cilium-builder-image.sh
CILIUM_BUILDER_IMAGE=quay.io/cilium/cilium-builder:b7a9dcdcadd77d38db87bbd06b9bc238e9dab5a0@sha256:eecc017a6ccf0c7884f1ffcf10e58462a272f5e41c0ece09adb351e8839e3157

.PHONY: all
all: proto doc

.PHONY: proto
proto: v1

.PHONY: v1
v1:
	docker container run --rm \
		--volume $(CURDIR)/v1:/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(CILIUM_BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc

.PHONY: doc
doc:
	docker container run --rm \
		--volume $(CURDIR)/v1:/out \
		--volume $(CURDIR)/v1/fgs:/protos \
		pseudomuto/protoc-gen-doc \
		--doc_opt=markdown,README.md
