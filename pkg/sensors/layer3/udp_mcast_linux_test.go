// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build sudo_tests

package layer3_test

import (
	"os/exec"
	"strings"
)

const (
	localhostIP4 = "127.0.0.1"
)

func storeMSB(buf []byte, index uint, size uint, value uint) {
	if size == 0 {
		return
	}
	for i := uint(0); i < size; i++ {
		buf[index+i] = byte((value >> ((size - i - 1) * 8)) & 0xff)
	}
}

func getDefaultInterfaceAddress() (string, error) {
	defaultRoute, err := exec.Command("bash", "-c", "ip r | grep default").Output()
	if err != nil {
		return "", err
	}
	defaultRouteFields := strings.Fields(string(defaultRoute))
	ifAddr := defaultRouteFields[8]
	return ifAddr, nil
}
