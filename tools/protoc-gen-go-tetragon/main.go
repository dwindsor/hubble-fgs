package main

import (
	"fmt"

	"github.com/cilium/tetragon/tools/protoc-gen-go-tetragon/generate"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	protogen.Options{}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)
		for _, generator := range generate.Generators {
			if err := generator(gen, gen.Files); err != nil {
				return fmt.Errorf("Failed to generate file: %v", err)
			}
		}
		return nil
	})
}
