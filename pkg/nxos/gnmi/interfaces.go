// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package gnmi

import (
	"context"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
)

// SubscriptionCallback is the signature for handlers registered with the subscription handler.
// It receives the path, the raw update (for backward compatibility with stores),
// and whether this is a delete notification.
type SubscriptionCallback func(path string, update *gnmiproto.Update, isDelete bool)

// handlerRegistration holds a handler and its associated subscription paths.
type handlerRegistration struct {
	handler           SubscriptionCallback
	subscriptionPaths []string
}

// subscriptionEntry tracks a subscription's context.
type subscriptionEntry struct {
	cancel context.CancelFunc
	paths  []string
}

// GnmiHandler provides path-based gNMI operations with automatic retry.
// This is the main interface for interacting with gNMI.
type GnmiHandler interface {
	// Connection management
	Close() error

	// Path-based GET with automatic retry and JSON encoding.
	// Returns string values extracted from the response.
	Get(ctx context.Context, path string) ([]string, error)

	// Path-based SET with automatic retry and JSON encoding.
	// Accepts any value type and converts it appropriately.
	Set(ctx context.Context, path string, value any) error

	// Delete performs a gNMI DELETE operation.
	Delete(ctx context.Context, path string) error

	// RegisterHandler registers a callback for specific subscription paths.
	// When a notification is received for a path that matches one of the
	// subscriptionPaths, the handler will be called. Multiple handlers can
	// register for the same path - all matching handlers receive the notification.
	RegisterHandler(handler SubscriptionCallback, subscriptionPaths ...string)

	// UnregisterHandler removes a handler by its callback reference.
	UnregisterHandler(handler SubscriptionCallback)

	// StartSubscriptions collects the union of all registered handlers'
	// subscription paths, deduplicates them, and starts a single gNMI
	// subscription. Only one subscription may be active at a time.
	StartSubscriptions(ctx context.Context)

	// StopSubscriptions stops the active subscription.
	StopSubscriptions()
}
