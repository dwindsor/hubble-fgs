FGS_PROTO_SOURCES := \
	./fgs/fgs.proto \

FGS_GO_TARGETS := \
	$(FGS_PROTO_SOURCES:.proto=.pb.go) \
	$(FGS_PROTO_SOURCES:.proto=.pb.validate.go) \
	$(FGS_PROTO_SOURCES:.proto=.pb.json.go) \

FGS_PROTOC_PLUGINS := \
	--plugin=../../tools/protoc-gen-go \
	--plugin=../../tools/protoc-gen-go-json \
	--plugin=../../tools/protoc-gen-validate \

$(FGS_GO_TARGETS): $(FGS_PROTO_SOURCES) deps
	set -e; \
	for proto in $(FGS_PROTO_SOURCES) ; do \
		protoc --lint_out=. $${proto}; \
		protoc $(FGS_PROTOC_PLUGINS) --go_out=plugins=grpc:. --validate_out=lang=go:. --go-json_out=orig_name:. $${proto}; \
	done

all: $(FGS_GO_TARGETS)

clean:
	rm -f $(FGS_GO_TARGETS)

deps:
	@protoc --version | grep 3.11.4 || (echo "Error: protoc 3.11.4 is required" && exit 1)

.PHONY: all clean dep
