// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// The nocloud tag gates the AWS SDK out of the slim tetrabox binary. The slim
// build therefore omits S3 sources; these stubs preserve the package API and
// return a clear error when an S3 source is requested.
//go:build nocloud

package exec

import (
	"errors"
	"time"

	appModelV1 "github.com/isovalent/ipa/application_model/v1alpha"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var errS3Unsupported = errors.New("S3 source is not supported in this build")

func s3FetchAlerts(_ string) (map[string][]*tetragon.Alert, map[string]int, error) {
	return nil, nil, errS3Unsupported
}

func s3FetchAppModel(_ string, _ []string) (*appModelV1.ApplicationModelEvent, error) {
	return nil, errS3Unsupported
}

func s3Monitor(_ string, _ time.Duration, _ []string) error {
	return errS3Unsupported
}

func s3MonitorAlert(_ string, _ time.Duration, _ []string) error {
	return errS3Unsupported
}
