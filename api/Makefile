# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go
BUILDER_IMAGE=isovalent/tetragon-codegen:latest

.PHONY: all
all: proto

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
		--volume $(CURDIR)/v1:/src \
		--user "$(shell id -u):$(shell id -g)" \
		$(BUILDER_IMAGE) \
		make -C /src -f Makefile.protoc

.PHONY: doc
doc:
	docker container run --rm \
		--volume $(CURDIR)/v1:/out \
		--volume $(CURDIR)/../modules/tetragon-oss/api/v1/tetragon/capabilities.proto:/protos/tetragon/capabilities.proto \
		--volume $(CURDIR)/v1/fgs/fgs.proto:/protos/fgs.proto \
		--volume $(CURDIR)/../modules/tetragon-oss/api/v1/tetragon/tetragon.proto:/protos/tetragon.proto \
		--volume $(CURDIR)/v1/fgs/dns.proto:/protos/dns.proto \
		--volume $(CURDIR)/v1/fgs/events.proto:/protos/events.proto \
		--volume $(CURDIR)/v1/fgs/sensors.proto:/protos/sensors.proto \
		--volume $(CURDIR)/../modules/tetragon-oss/api/v1/tetragon/stack.proto:/protos/stack.proto \
		pseudomuto/protoc-gen-doc:1.5.0 \
		--doc_opt=markdown,README.md

.PHONY: vendor
vendor:
	$(GO) mod tidy
	$(GO) mod vendor
	$(GO) mod verify
