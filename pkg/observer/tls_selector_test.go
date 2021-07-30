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
package observer

import (
	"bytes"
	"testing"

	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
)

func TestInitKernelSelectors(t *testing.T) {
	expected := []byte{
		// spec header
		0x01, 0x00, 0x00, 0x00, // single selector

		0x4, 0x00, 0x00, 0x00, // selector offset list

		// Size of selector
		16, 0x00, 0x00, 0x00,

		// selector header size 4
		0x2, 0x00, 0x00, 0x00, // size = #ofPorts * sizeof(uint32)

		// port values
		1, 187, 0x00, 0x00, // 0x01 0xbb -> port 443
		3, 225, 0x00, 0x00, // 0x03 0xe1 -> port 993
	}

	matchPorts := []uint32{443, 993}
	selectors := []v1alpha1.TlsSelector{
		{
			MatchPorts: matchPorts,
		},
	}
	spec := v1alpha1.TlsSpec{
		Enable:    true,
		Mode:      "tc",
		Selectors: selectors,
	}
	b, _ := ParseTlsSpec(&spec)
	if bytes.Equal(expected[0:len(expected)], b[0:len(expected)]) == false {
		t.Errorf("ParseTlsSpec: expected %v bytes %v\n", expected, b[0:len(expected)])
	}
}
