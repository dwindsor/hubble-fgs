// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build lseg

package option

// This file will be included iff "lseg" is included in the go build tags. It adds
// a multicast app that is specific to LSEG.

// Explicitly state the app IDs. These must match the same in the BPF code.
const (
	MulticastAppLSEGMTP MulticastAppID = 1
)

func init() {
	multicastAppID["LSEG-MTP"] = MulticastAppLSEGMTP
}
