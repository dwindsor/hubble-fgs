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

package enterprise

import (
	"flag"

	// Import flags from OSS so they get initialized here.
	_ "github.com/cilium/tetragon/tests/e2e/flags"
)

func init() {
	flag.CommandLine.Set("tetragon.helm.set", "enterprise.exportAllowList=")
	flag.CommandLine.Set("tetragon.helm.daemonset", "hubble-enterprise")
	flag.CommandLine.Set("tetragon.helm.url", "https://helm.isovalent.com")
	flag.CommandLine.Set("tetragon.helm.chart", "isovalent/hubble-enterprise")
}
