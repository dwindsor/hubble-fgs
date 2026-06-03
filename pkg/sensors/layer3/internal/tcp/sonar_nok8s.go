// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

//go:build linux && nok8s

// AWS Sonar export pulls in the AWS SDK, which the slim nok8s build drops.
package tcp

import (
	"context"
)

// sonarStats stays declared so the shared socket-close cleanup compiles; it is
// never enabled in the slim build, so its cache is nil and cleanup is a no-op.
var sonarStats statsManager

func InitSonar(_ context.Context) {
}
