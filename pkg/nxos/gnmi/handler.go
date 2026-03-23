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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/gnmic/pkg/api/target"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

const (
	// maxRetries is the maximum number of retry attempts for gNMI operations.
	maxRetries = 4
	// baseRetryDelay is the initial delay between retry attempts.
	baseRetryDelay = time.Second
)

// NxosGnmiHandler wraps the gnmic target.Target to implement GnmiHandler interface
// for NXOS hardware connections.
type NxosGnmiHandler struct {
	target              *target.Target
	config              *HandlerConfig
	mu                  sync.RWMutex
	closed              bool
	subscriptionCounter uint64

	// Low-level subscription state (gnmic target subscriptions)
	subscriptions map[string]subscriptionEntry

	// Subscription routing state
	handlers   []handlerRegistration // registered handlers with their subscription paths
	subCtx     context.Context
	subCancel  context.CancelFunc
	subStarted bool
}

// NewNxosGnmiHandler creates a new NxosGnmiHandler with the given configuration.
// It creates the gNMI target, connects the client, and verifies the connection
// by performing a capabilities request.
func NewNxosGnmiHandler(ctx context.Context, config *HandlerConfig) (*NxosGnmiHandler, error) {
	if config == nil {
		config = DefaultHandlerConfig()
	}

	if config.Address == "" {
		var err error
		config, err = LoadCredentialsFromEnvAndConfig(DefaultSASConfigFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load gnmi config from environment")
		}
	}

	// Build target options
	opts := []api.TargetOption{
		api.Name("sswitch"),
		api.Address(config.Address),
	}

	if config.Username != "" {
		opts = append(opts, api.Username(config.Username))
	}
	if config.Password != "" {
		opts = append(opts, api.Password(config.Password))
	}
	if config.Timeout > 0 {
		opts = append(opts, api.Timeout(config.Timeout))
	}
	if config.Insecure {
		opts = append(opts, api.Insecure(true))
	}
	if config.SkipVerify {
		opts = append(opts, api.SkipVerify(true))
	}
	if config.TLSCA != "" {
		opts = append(opts, api.TLSCA(config.TLSCA))
	}
	if config.TLSCert != "" {
		opts = append(opts, api.TLSCert(config.TLSCert))
	}
	if config.TLSKey != "" {
		opts = append(opts, api.TLSKey(config.TLSKey))
	}

	t, err := api.NewTarget(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gNMI target: %w", err)
	}

	h := &NxosGnmiHandler{
		target:        t,
		config:        config,
		subscriptions: make(map[string]subscriptionEntry),
		handlers:      nil,
	}

	// Create gNMI client connection
	logger.GetLogger().Info("Creating gNMI client connection", "address", config.Address)
	err = t.CreateGNMIClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create gNMI client: %w", err)
	}

	// Getting gNMI server details
	caps, err := h.target.Capabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("capabilities request failed: %w", err)
	}
	logger.GetLogger().Info("Connected to gNMI server", "version", caps.GetGNMIVersion())

	return h, nil
}

// Get performs a gNMI Get operation for a path string with automatic retry.
// Returns string values extracted from the response.
func (h *NxosGnmiHandler) Get(ctx context.Context, path string) ([]string, error) {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return nil, fmt.Errorf("handler is closed")
	}
	h.mu.RUnlock()

	var lastErr error
	delay := baseRetryDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := api.NewGetRequest(
			api.Path(path),
			api.Encoding("json"),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create get request: %w", err)
		}

		resp, err := h.target.Get(ctx, req)
		if err == nil {
			return extractStrings(resp), nil
		}
		lastErr = err

		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
			logger.GetLogger().Debug("gNMI Get retry", "path", path, "attempt", attempt, "error", err)
		}
	}

	return nil, fmt.Errorf("gNMI Get failed after %d retries: %w", maxRetries, lastErr)
}

// Set performs a gNMI Set operation with automatic retry.
// The value is JSON-encoded before sending, as NX-OS gNMI only accepts JSON-encoded values.
func (h *NxosGnmiHandler) Set(ctx context.Context, path string, value any) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return fmt.Errorf("handler is closed")
	}
	h.mu.RUnlock()

	// JSON-encode the value — NX-OS gNMI only accepts JSON-encoded values
	jsonStr, err := marshalJSONValue(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value to JSON: %w", err)
	}

	req, err := api.NewSetRequest(
		api.Update(
			api.Path(path),
			api.Value(jsonStr, "json")),
	)
	if err != nil {
		return fmt.Errorf("failed to create set request: %w", err)
	}

	var lastErr error
	delay := baseRetryDelay

	for attempt := 1; attempt <= maxRetries; attempt++ {
		_, err := h.target.Set(ctx, req)
		if err == nil {
			return nil
		}
		lastErr = err

		if attempt < maxRetries {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
				delay *= 2
			}
			logger.GetLogger().Debug("gNMI Set retry", "path", path, "attempt", attempt, "error", err)
		}
	}

	return fmt.Errorf("gNMI Set failed after %d retries: %w", maxRetries, lastErr)
}

// Delete performs a gNMI Delete operation.
func (h *NxosGnmiHandler) Delete(ctx context.Context, path string) error {
	h.mu.RLock()
	if h.closed {
		h.mu.RUnlock()
		return fmt.Errorf("handler is closed")
	}
	h.mu.RUnlock()

	gnmiPath := paths.StringToPath(path)
	req := &gnmiproto.SetRequest{Delete: []*gnmiproto.Path{gnmiPath}}

	_, err := h.target.Set(ctx, req)
	if err != nil {
		logger.GetLogger().Error("gNMI delete failed", "path", path, "error", err)
		return err
	}
	return nil
}

// RegisterHandler registers a callback for specific subscription paths.
func (h *NxosGnmiHandler) RegisterHandler(handler SubscriptionCallback, subscriptionPaths ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.GetLogger().Debug("Registering subscription handler", "subscriptionPaths", subscriptionPaths)
	h.handlers = append(h.handlers, handlerRegistration{
		handler:           handler,
		subscriptionPaths: subscriptionPaths,
	})
}

// UnregisterHandler removes a handler by its callback reference.
func (h *NxosGnmiHandler) UnregisterHandler(handler SubscriptionCallback) {
	h.mu.Lock()
	defer h.mu.Unlock()

	logger.GetLogger().Debug("Unregistering subscription handler")
	for i, reg := range h.handlers {
		// Compare function pointers
		if &reg.handler == &handler {
			h.handlers = append(h.handlers[:i], h.handlers[i+1:]...)
			return
		}
	}
}

// StartSubscriptions collects the union of all registered handlers'
// subscription paths, deduplicates them, and starts a single gNMI subscription.
// Only one subscription may be active at a time.
func (h *NxosGnmiHandler) StartSubscriptions(ctx context.Context) {
	h.mu.Lock()
	if h.subStarted {
		h.mu.Unlock()
		logger.GetLogger().Debug("Subscriptions already started")
		return
	}
	h.subStarted = true
	h.subCtx, h.subCancel = context.WithCancel(ctx)

	// Collect and deduplicate all subscription paths from registered handlers
	pathSet := make(map[string]struct{})
	for _, reg := range h.handlers {
		for _, p := range reg.subscriptionPaths {
			pathSet[p] = struct{}{}
		}
	}
	allPaths := make([]string, 0, len(pathSet))
	for p := range pathSet {
		allPaths = append(allPaths, p)
	}

	subCtx := h.subCtx
	h.mu.Unlock()

	logger.GetLogger().Info("Starting gnmi subscriptions")

	go func() {
		h.subscribe(subCtx, allPaths)
	}()
}

// StopSubscriptions stops all active subscriptions, including both the
// high-level subscription context and all individual low-level subscriptions.
func (h *NxosGnmiHandler) StopSubscriptions() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.stopSubscriptionsLocked()
}

// stopSubscriptionsLocked stops all subscriptions. Caller must hold the handler lock.
func (h *NxosGnmiHandler) stopSubscriptionsLocked() {
	if !h.subStarted {
		return
	}

	logger.GetLogger().Info("Stopping gnmi subscriptions")
	h.subStarted = false
	if h.subCancel != nil {
		h.subCancel()
	}

	// Cancel all individual subscriptions
	for name, entry := range h.subscriptions {
		logger.GetLogger().Debug("Canceling subscription", "name", name)
		entry.cancel()
	}
	h.subscriptions = make(map[string]subscriptionEntry)
}

// route finds all handlers that subscribed to the notification path and calls them.
// A handler matches if the notification path matches any of its subscription paths.
// Matching accounts for gNMI selectors (e.g., [name=default]) that may appear in
// notification paths but not in subscription patterns.
func (h *NxosGnmiHandler) route(path string, update *gnmiproto.Update, isDelete bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// If the path is "System" (root level), dispatch to all handlers
	// since the JSON payload may contain data for any of them
	if path == "System" {
		logger.GetLogger().Debug("Root System update, dispatching to all handlers", "handlerCount", len(h.handlers))
		for _, reg := range h.handlers {
			reg.handler(path, update, isDelete)
		}
		return
	}

	// Find all handlers that subscribed to this path
	matched := false
	for _, reg := range h.handlers {
		for _, subPath := range reg.subscriptionPaths {
			if paths.PathMatchesPrefix(path, subPath) {
				reg.handler(path, update, isDelete)
				matched = true
				break // Only call handler once even if multiple paths match
			}
		}
	}

	if !matched {
		logger.GetLogger().Debug("No handler found for path", "path", path)
	}
}

// subscribe subscribes to paths and routes notifications via Route.
func (h *NxosGnmiHandler) subscribe(ctx context.Context, paths []string) error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return fmt.Errorf("handler is closed")
	}

	// Create child context for this subscription
	childCtx, cancel := context.WithCancel(ctx)

	// Generate unique subscription name
	subscriptionName := fmt.Sprintf("subscription-%d", atomic.AddUint64(&h.subscriptionCounter, 1))
	h.subscriptions[subscriptionName] = subscriptionEntry{
		cancel: cancel,
		paths:  paths,
	}
	h.mu.Unlock()

	logger.GetLogger().Debug("Starting gNMI subscription", "name", subscriptionName, "paths", paths)

	// Build subscribe request with PROTO encoding
	opts := []api.GNMIOption{
		api.SubscriptionListMode("stream"),
		api.EncodingPROTO(),
	}
	for _, p := range paths {
		opts = append(opts, api.Subscription(
			api.Path(p),
			api.SubscriptionMode("on_change"),
		))
	}

	req, err := api.NewSubscribeRequest(opts...)
	if err != nil {
		cancel()
		return fmt.Errorf("failed to create subscribe request: %w", err)
	}

	// Start subscription in background
	go h.subscriptionLoop(childCtx, req, subscriptionName)

	return nil
}

// subscriptionLoop reads subscription responses and routes to handlers by path.
func (h *NxosGnmiHandler) subscriptionLoop(ctx context.Context, req *gnmiproto.SubscribeRequest, subscriptionName string) {
	defer func() {
		h.mu.Lock()
		delete(h.subscriptions, subscriptionName)
		h.mu.Unlock()
	}()

	go h.target.Subscribe(ctx, req, subscriptionName)
	respChan, errChan := h.target.ReadSubscriptions()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errChan:
			if err != nil && err.Err != nil {
				logger.GetLogger().Error("Subscription error", "name", subscriptionName, "error", err.Err)
			}
		case resp, ok := <-respChan:
			if !ok {
				logger.GetLogger().Info("Subscription channel closed", "name", subscriptionName)
				return
			}
			if resp == nil || resp.Response == nil {
				continue
			}

			// Parse path from response and route to handler
			switch r := resp.Response.Response.(type) {
			case *gnmiproto.SubscribeResponse_Update:
				notification := r.Update

				// Handle updates
				for _, update := range notification.GetUpdate() {
					path := paths.PathToString(notification.GetPrefix(), update.GetPath())
					h.route(path, update, false)
				}

				// Handle deletes
				for _, deletePath := range notification.GetDelete() {
					path := paths.PathToString(notification.GetPrefix(), deletePath)
					h.route(path, nil, true)
				}
			case *gnmiproto.SubscribeResponse_SyncResponse:
				logger.GetLogger().Debug("Subscription sync complete", "name", subscriptionName)
			default:
				logger.GetLogger().Debug("Unknown subscription response type", "name", subscriptionName)
			}
		}
	}
}

// Close closes the gNMI connection and cleans up resources.
func (h *NxosGnmiHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.closed {
		return nil
	}

	logger.GetLogger().Info("Closing gNMI handler")
	h.closed = true

	// Stop all subscriptions
	h.stopSubscriptionsLocked()

	if h.target != nil {
		return h.target.Close()
	}
	return nil
}
