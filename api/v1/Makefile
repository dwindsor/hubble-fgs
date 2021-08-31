FGS_PROTO_SOURCES := \
	./fgs/fgs.proto \

FGS_GO_TARGETS := \
	$(FGS_PROTO_SOURCES:.proto=.pb.go) \
	$(FGS_PROTO_SOURCES:.proto=.pb.validate.go) \
	$(FGS_PROTO_SOURCES:.proto=.pb.json.go) \

FGS_PROTOC_PLUGINS := \
	--plugin=../../tools/protoc-gen-go \
	--plugin=../../tools/protoc-gen-go-grpc \
	--plugin=../../tools/protoc-gen-go-json \

$(FGS_GO_TARGETS): $(FGS_PROTO_SOURCES) deps
	set -e; \
	for proto in $(FGS_PROTO_SOURCES) ; do \
		protoc --lint_out=. $${proto}; \
		protoc $(FGS_PROTOC_PLUGINS) \
		--go_out=paths=source_relative:. \
		--go-grpc_out=requireUnimplementedServers=false,paths=source_relative:. \
		--go-json_out=orig_name=true,paths=source_relative:. \
		$${proto}; \
	done

all: $(FGS_GO_TARGETS) doc

doc:
	docker run --rm -v $(shell pwd):/out -v $(shell pwd)/fgs:/protos pseudomuto/protoc-gen-doc --doc_opt=markdown,$@

clean:
	rm -f $(FGS_GO_TARGETS)

deps:
	@protoc --version | grep 3.17.3 || (echo "Error: protoc 3.17.3 is required" && exit 1)

.PHONY: all clean dep doc
