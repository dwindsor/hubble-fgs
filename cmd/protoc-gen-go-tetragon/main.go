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
	"github.com/cilium/tetragon/cmd/protoc-gen-go-tetragon/common"
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

	generate.Generators = append(generate.Generators, eventcache.Generate)

	generate.Generate()
}
