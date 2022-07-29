# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

GO ?= go
BUILDER_IMAGE=isovalent/tetragon-codegen:latest

.PHONY: all
all: proto

.PHONY: proto
proto: v1

.PHONY: v1
v1:
	docker container run --rm \
		--volume $(CURDIR)/v1:/src \
		--volume $(CURDIR)/../modules/tetragon-oss/api/v1/tetragon:/tetragon \
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
	$(GO) mod tidy -compat=1.17
	$(GO) mod vendor
	$(GO) mod verify
