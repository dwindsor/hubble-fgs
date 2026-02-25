// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package logexport

import "log/slog"

// ExportKey is the slog attribute key used to tag log records for export
// to FluentBit. Add logexport.Export to any slog call to mark it for
// forwarding:
//
//	logger.Info("message", "key", val, logexport.Export)
const ExportKey = "flb_export"

// Export is a sentinel slog.Attr that marks a log record for export to
// FluentBit. Untagged records are silently dropped by the export handler.
var Export = slog.Bool(ExportKey, true)
