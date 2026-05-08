// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build windows

package server

func initContainerIDMap() error {
	return nil
}

func getContainerID(cgroupid uint64, dummy any) (string, bool) {
	return "", false
}

// newKtimeConverter returns a zero-value converter on Windows. Windows does
// not run real BPF sensors, so returning nil timestamps from convert() is
// correct behavior.
func newKtimeConverter() ktimeConverter {
	return ktimeConverter{}
}
