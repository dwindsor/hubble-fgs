//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package main

import (
	"fmt"
	"reflect"

	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
	ossEventcache "github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/eventcache"
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/generate"
	"github.com/isovalent/hubble-fgs/cmd/protoc-gen-go-tetragon/eventcache"
)

func main() {
	common.TetragonCopyrightHeader = `//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//`
	common.TetragonPackageName = `github.com/isovalent/hubble-fgs`
	common.TetragonApiPackageName = `api/v1/fgs`

	removeGenerator(ossEventcache.Generate)
	generate.Generators = append(generate.Generators, eventcache.Generate)

	generate.Generate()
}

// Removes a registered generator, useful for replacing oss generators with enterprise ones
func removeGenerator(gen generate.GeneratorFunc) error {
	for i, elem := range generate.Generators {
		if reflect.ValueOf(elem) == reflect.ValueOf(gen) {
			generate.Generators = append(generate.Generators[:i], generate.Generators[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("Failed to find registered generator function %v", gen)
}
