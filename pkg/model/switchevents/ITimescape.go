// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

// Package switchevents provides interfaces and types for managing timescape events.

package switchevents

import (
	"context"
)

// Timescape manages timescape event reporting
type ITimescape interface {
	// Start begins timescape event monitoring and reporting
	Start(ctx context.Context) error
	// Stop terminates timescape event monitoring
	Stop(ctx context.Context)
	// ReportSystemStatus triggers a system status report
	ReportSystemStatus(ctx context.Context) error
	// ReportPolicyStatus triggers a policy status report
	ReportPolicyStatus(ctx context.Context) error
}
