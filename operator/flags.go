// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strings"

	"github.com/isovalent/hubble-fgs/operator/option"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	initializeFlags()
}

func initializeFlags() {
	cobra.OnInitialize(func() {
		replacer := strings.NewReplacer("-", "_", ".", "_")
		viper.SetEnvKeyReplacer(replacer)
		viper.SetEnvPrefix(option.TetragonOpEnvPrefix)
		viper.AutomaticEnv()
	})

	flags := rootCmd.Flags()

	flags.String(option.CMDRef, "", "Path to cmdref output directory")
	flags.MarkHidden(option.CMDRef)

	flags.Bool(option.SkipCRDCreation, false, "When true, Kubernetes Custom Resource Definitions will not be created")

	viper.BindPFlags(flags)
}

// Populate sets all options with the values from viper.
func configPopulate() {
	option.Config.SkipCRDCreation = viper.GetBool(option.SkipCRDCreation)
}
