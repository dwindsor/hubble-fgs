//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package sockmap

import (
	"github.com/isovalent/hubble-fgs/pkg/k8s/apis/isovalent.com/v1alpha1"
	"github.com/isovalent/hubble-fgs/pkg/selectors"
	"github.com/isovalent/hubble-fgs/pkg/sensors/utils"
)

func parseTLSSelector(k *selectors.KernelSelectorState, s v1alpha1.TlsSelector) error {
	return utils.ParseMatchPorts(k, s.MatchPorts)
}

// ParseTLSSpec parses the input yaml/crd and outputs the kernel selectors
// needed for BPF to run match logic.
//
// TLS selector layout is the following.
//    #OfSelectors         uint32
//    OffsetOfEachSelector uint32
//    #OfMatchPorts        uint32
//    Port1 .... PortN     uint32, uint32, ...
func ParseTLSSpec(spec *v1alpha1.TlsSpec) ([128]byte, error) {
	var match [128]byte
	var e [4096]byte
	k := &selectors.KernelSelectorState{}

	if len(spec.Selectors) == 0 {
		selectors.WriteSelectorInt32(k, -1)
	} else {

		selectors.WriteSelectorUint32(k, uint32(len(spec.Selectors)))
		soff := make([]uint32, len(spec.Selectors))
		for i, _ := range spec.Selectors {
			soff[i] = selectors.AdvanceSelectorLength(k)
		}

		for i, s := range spec.Selectors {
			selectors.WriteSelectorLength(k, soff[i])
			loff := selectors.AdvanceSelectorLength(k)
			if err := parseTLSSelector(k, s); err != nil {
				return match, err
			}
			selectors.WriteSelectorLength(k, loff)
		}
	}

	e = selectors.GetSelectorBuffer(k)
	copy(match[:], e[:128])
	return match, nil
}
