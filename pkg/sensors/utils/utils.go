//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package utils

import (
	"github.com/isovalent/hubble-fgs/pkg/api"
	"github.com/isovalent/hubble-fgs/pkg/kernels"
	"github.com/isovalent/hubble-fgs/pkg/selectors"
)

// SkSkbParserRequired returns whether the underlying kernel requires skskb
// parsing.
func SkSkbParserRequired() bool {
	// The skskb parser is only needed on 5.10 and earlier kernels.
	// After 5.10 we can run with only the skskb verdict programs
	// improving performance.
	return !kernels.MinKernelVersion("5.10.0")
}

// ParseMatchPorts parses the matchPorts portion of a policy into the
// KernelSelectorState.
func ParseMatchPorts(k *selectors.KernelSelectorState, matchPorts []uint32) error {
	selectors.WriteSelectorUint32(k, uint32(len(matchPorts)))
	for _, port := range matchPorts {
		/* Some byte hackery here because ports are 16bits in packet, but
		 * we use them as 32bit types (this helps code generation and verifier)
		 * throughout BPF side. But we swap here to avoid doing the swap on data
		 * read from sock/packet.
		 */
		selectors.WriteSelectorUint32(k, uint32(api.SwapByte(uint16(port))))
	}
	return nil
}
