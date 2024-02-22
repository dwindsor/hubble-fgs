# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# renovate: datasource=docker
BUILDER_IMAGE=quay.io/cilium/cilium-builder@sha256:a2036a3f6420647e6702695dabd2ffa4d2832db45157042d0255bdc707b8e1f2
GO ?= go

.PHONY: all
all: proto doc

.PHONY: proto
proto: v1

.PHONY: copy_oss_files
copy_oss_files:
	for oss_file in  $(CURDIR)/../modules/tetragon-oss/api/v1/tetragon/*.proto; do \
		dst_file="v1/tetragon/$$(basename $$oss_file)"; \
		if [ $$dst_file = "v1/tetragon/events.proto" ]; then \
			echo "Skipping $$dst_file"; \
			continue; \
		fi; \
		echo "$$oss_file -> $$dst_file"; \
		truncate -s 0 $$dst_file; \
		printf '// This file is copied from OSS, DO NOT EDIT\n\n' >> $$dst_file; \
		cat $$oss_file >> $$dst_file; \
	done

.PHONY: v1
v1: copy_oss_files
	docker container run --rm \
		--volume $(CURDIR)/..:/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		make -C /src/api/v1 -f Makefile.protoc

.PHONY: doc
doc: copy_oss_files
	docker container run --rm \
		--volume $(CURDIR)/v1:/out \
		--volume $(CURDIR)/v1/:/protos \
		pseudomuto/protoc-gen-doc:1.5.0 \
		--doc_opt=markdown,README.md \
		$(patsubst $(CURDIR)/v1/%,%,$(wildcard $(CURDIR)/v1/tetragon/*.proto))

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
