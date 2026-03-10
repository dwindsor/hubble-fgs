// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build !windows

package option

import (
	"testing"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/assert"
)

func Test_validateConfigAppModelCGIDMap(t *testing.T) {
	oldConfig := Config
	oldOSSConfig := option.Config
	defer func() {
		Config = oldConfig
		option.Config = oldOSSConfig
	}()
	Config.EnableApplicationModel = true
	option.Config.EnableCgIDmap = false
	err := validateConfig(Config)
	assert.EqualError(t, err, "application model requires --enable-cgidmap")
}
