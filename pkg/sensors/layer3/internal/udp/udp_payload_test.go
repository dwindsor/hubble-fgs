// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package udp

import (
	"testing"
	"time"
)

func TestParseDnsMessageSkipAnswerError(t *testing.T) {
	dnsHeader := []byte{
		0x12, 0x34, 0x81, 0x80, // ID=0x1234, Flags=0x8180 (response)
		0x00, 0x01, 0x00, 0x02, // Questions=1, Answers=2
		0x00, 0x00, 0x00, 0x00, // Authority=0, Additional=0
	}

	question := []byte{
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // Label: "example" (length 7)
		0x03, 'c', 'o', 'm', // Label: "com" (length 3)
		0x00, 0x00, 0x01, 0x00, 0x01, // End=0x00, Type=A, Class=IN
	}

	validAnswer := []byte{
		0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, // Name=ptr(0x0C), Type=A, Class=IN
		0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, // TTL=60, RDLength=4
		0x08, 0x08, 0x08, 0x08, // IP=8.8.8.8
	}

	malformedAnswer := []byte{
		0xC0, 0x0C, 0x00, 0x02, 0x00, 0x01, // Name=ptr(0x0C), Type=NS, Class=IN
		0x00, 0x00, 0x00, 0x3C, 0x00, 0xFF, // TTL=60, RDLength=255 (but only 4 bytes follow)
		0x03, 'n', 's', '1', // Truncated RDATA
	}

	dnsBuf := append(append(append(dnsHeader, question...), validAnswer...), malformedAnswer...)

	resultChan := make(chan error, 1)

	go func() {
		_, err := parseDNSMessage(dnsBuf)
		resultChan <- err
	}()

	select {
	case err := <-resultChan:
		if err != nil {
			t.Logf("parseDnsMessage returned error: %v", err)
		} else {
			t.Log("parseDnsMessage completed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parseDnsMessage stuck in infinite loop")
	}
}
