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

package reader

import (
	"testing"

	api "github.com/isovalent/hubble-fgs/pkg/api/tlsapi"
	"github.com/stretchr/testify/assert"
)

func TestGetTLSCipher(t *testing.T) {
	assert.Equal(t, "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
		GetTLSCiphers(&api.FLV64{Length: 2, Value: [64]uint8{0xC0, 0x1C}})) // known value
	assert.Equal(t, "0xffff",
		GetTLSCiphers(&api.FLV64{Length: 2, Value: [64]uint8{0xff, 0xff}})) // unknown value
}
