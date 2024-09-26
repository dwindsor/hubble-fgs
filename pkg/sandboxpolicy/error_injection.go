//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sandboxpolicy

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func errorInjectionEntries() (map[string]struct{}, error) {
	fname := "/sys/kernel/debug/error_injection/list"
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ret := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		fs := strings.Fields(l)
		if strings.Contains(fs[0], "sys_") {
			ret[fs[0]] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("no injection list entries")
	}

	return ret, nil
}
