// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build nocloud

package local

// getCloudMetadataService is the nocloud stub: the cloud provider SDKs (AWS,
// GCloud, Azure) are compiled out, so no cloud environment is ever handled and
// the caller falls back to its own handling.
func getCloudMetadataService() (MetadataService, bool, error) {
	return nil, false, nil
}
