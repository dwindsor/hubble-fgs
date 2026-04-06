// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package device

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/viper"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/version"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi"
	"github.com/isovalent/hubble-fgs/pkg/nxos/storage"
)

// Default HSA port range constants.
const (
	DefaultHSAPortLow  uint16 = 28416
	DefaultHSAPortHigh uint16 = 28671

	// EnvHSAPortStart is the environment variable for the HSA port range start.
	EnvHSAPortStart = "NX_HSA_PORT_START"

	// EnvHSAPortEnd is the environment variable for the HSA port range end.
	EnvHSAPortEnd = "NX_HSA_PORT_END"
)

// deviceStore implements Store.
//
// Persistence contract: fields in this struct are NOT persisted by default.
// To persist a new field, you must explicitly:
//  1. Add it to storage.DeviceState in storage/storage.go
//  2. Include it in persist() below
//  3. Include it in the NewStore() load path above
//
// Do not persist runtime values (connection status, admission status, etc.) —
// only configuration values that must survive a process restart belong in storage.
type deviceStore struct {
	mu sync.RWMutex

	token              string
	proxyServer        string
	proxyPort          uint32
	connectionStatus   string
	admissionStatus    string
	rejectReason       string
	serialNumber       string
	model              string
	softwareVersion    string
	serviceIP          string
	controllerEndpoint string
	controllerPort     uint32
	controllerVersion  string
	cpaVersion         string
	systemState        int
	headlessMode       bool
	inService          string
	skipReg            bool
	skipRegReason      string
	reload             bool
	lbMode             string

	callbacks     map[int]func(Event)
	nextCbID      int
	storage       storage.Storage
	gnmiHandler   gnmi.GnmiHandler
	tokenProvider AgentTokenProvider

	hsaPortLow  uint16
	hsaPortHigh uint16

	// Hooks for in-service transitions, called by SetInService.
	preInServiceHook  func(ctx context.Context, newState string)
	postInServiceHook func(ctx context.Context, oldState string)
}

// AgentTokenProvider is an optional interface for advanced token processing.
// It is implemented by pkg/token.AgentToken and allows the device store to
// validate, persist, and extract controller info from K8s auth tokens without
// directly importing the heavy token package.
type AgentTokenProvider interface {
	ValidK8sAuth(token string) error
	SetAndPersistK8sAuthToken(token string) error
	K8sControllerEndpoint() (string, uint32, error)
}

// Option configures Store.
type Option func(*deviceStore)

// WithStorage sets the storage backend for the device store.
func WithStorage(s storage.Storage) Option {
	return func(ds *deviceStore) {
		ds.storage = s
	}
}

// WithGnmiHandler sets the gNMI handler for state synchronization.
func WithGnmiHandler(h gnmi.GnmiHandler) Option {
	return func(ds *deviceStore) {
		ds.gnmiHandler = h
	}
}

// WithAgentTokenProvider sets the token provider for advanced token processing.
func WithAgentTokenProvider(p AgentTokenProvider) Option {
	return func(ds *deviceStore) {
		ds.tokenProvider = p
	}
}

// WithHeadlessMode forces headless mode on, bypassing the /etc/sas.cfg check.
func WithHeadlessMode(headless bool) Option {
	return func(ds *deviceStore) {
		ds.headlessMode = headless
	}
}

// NewStore creates a new device store with optional storage backend.
// If storage is provided, it loads initial state and persists changes automatically.
func NewStore(ctx context.Context, opts ...Option) Store {
	s := &deviceStore{
		connectionStatus: CommonStateUnknown,
		admissionStatus:  CommonStateUnknown,
		hsaPortLow:       DefaultHSAPortLow,
		hsaPortHigh:      DefaultHSAPortHigh,
		callbacks:        make(map[int]func(Event)),
		cpaVersion:       version.Version,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Read HSA port range from environment variables, overriding defaults if valid.
	if startVal, endVal := os.Getenv(EnvHSAPortStart), os.Getenv(EnvHSAPortEnd); startVal != "" && endVal != "" {
		low, errLow := parsePort(startVal)
		high, errHigh := parsePort(endVal)
		if errLow != nil {
			logger.GetLogger().Warn("Invalid NX_HSA_PORT_START, using defaults", "value", startVal, "error", errLow)
		} else if errHigh != nil {
			logger.GetLogger().Warn("Invalid NX_HSA_PORT_END, using defaults", "value", endVal, "error", errHigh)
		} else if low >= high {
			logger.GetLogger().Warn("Invalid HSA port range: start must be less than end, using defaults", "start", low, "end", high)
		} else {
			s.hsaPortLow = low
			s.hsaPortHigh = high
			logger.GetLogger().Info("HSA port range configured from env", "low", low, "high", high)
		}
	}

	// Load initial state from storage if available
	if s.storage != nil {
		state, err := s.storage.LoadDevice(ctx)
		if err != nil && !storage.IsNotFound(err) {
			logger.GetLogger().Warn("Failed to load device state from storage", "error", err)
		}
		if state != nil {
			s.proxyServer = state.ProxyServer
			s.proxyPort = state.ProxyPort
			s.serviceIP = state.ServiceIP
			s.skipReg = state.SkipReg
			s.skipRegReason = state.SkipRegReason
			s.lbMode = state.LbMode
			logger.GetLogger().Info("Loaded device state from storage")
		}
	}

	if s.lbMode == "" {
		s.lbMode = "symmetric_hash"
	}

	// Parse headless mode from /etc/sas.cfg (overrides persisted state).
	v := viper.New()
	v.SetConfigFile("/etc/sas.cfg")
	v.SetConfigType("env")
	if err := v.ReadInConfig(); err != nil {
		logger.GetLogger().Error("Failed to read sas.cfg for headless mode", "error", err)
	} else if v.GetString("NX_AGENT_HEADLESS_MODE") == "1" {
		logger.GetLogger().Info("Headless mode set")
		s.headlessMode = true
	}

	// Non-headless mode: start with ConnPending since connection isn't established yet.
	if !s.headlessMode {
		s.systemState |= sysStConnPending
	}

	return s
}

func (s *deviceStore) Token() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token
}

func (s *deviceStore) ProxyServer() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyServer
}

func (s *deviceStore) ProxyPort() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyPort
}

func (s *deviceStore) ProxyAddress() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.proxyServer == "" {
		return ""
	}
	if s.proxyPort == 0 {
		return s.proxyServer
	}
	return fmt.Sprintf("%s:%d", s.proxyServer, s.proxyPort)
}

func (s *deviceStore) ConnectionStatus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.connectionStatus
}

func (s *deviceStore) AdmissionStatus() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.admissionStatus
}

func (s *deviceStore) SerialNumber() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serialNumber
}

func (s *deviceStore) Model() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.model
}

func (s *deviceStore) SoftwareVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.softwareVersion
}

func (s *deviceStore) ServiceIP() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serviceIP
}

func (s *deviceStore) ControllerEndpoint() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controllerEndpoint
}

func (s *deviceStore) ControllerPort() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controllerPort
}

func (s *deviceStore) ControllerVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.controllerVersion
}

func (s *deviceStore) CPAVersion() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cpaVersion
}

func (s *deviceStore) SystemState() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.systemState
}

func (s *deviceStore) RejectReason() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.rejectReason
}

func (s *deviceStore) SkipReg() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.skipReg
}

func (s *deviceStore) SkipRegReason() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.skipRegReason
}

func (s *deviceStore) IsHeadlessMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.headlessMode
}

func (s *deviceStore) InServiceState() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inService
}

func (s *deviceStore) IsInService() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inService == InServiceStateInService
}

func (s *deviceStore) LbMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lbMode
}

func (s *deviceStore) HSAPortLow() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hsaPortLow
}

// IsSkipReg returns (skipReg, reload, reason).
// The reload flag uses read-once semantics: it is cleared atomically on each call.
// Callers should use IsHeadlessMode() separately for headless mode status.
func (s *deviceStore) IsSkipReg() (bool, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	skipReg := s.skipReg
	reload := s.reload
	s.reload = false
	return skipReg, reload, s.skipRegReason
}

func (s *deviceStore) Watch(callback func(Event)) func() {
	s.mu.Lock()
	id := s.nextCbID
	s.nextCbID++
	s.callbacks[id] = callback
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.callbacks, id)
	}
}

func (s *deviceStore) notify(event Event) {
	s.mu.RLock()
	callbacks := make([]func(Event), 0, len(s.callbacks))
	for _, cb := range s.callbacks {
		callbacks = append(callbacks, cb)
	}
	s.mu.RUnlock()

	for _, cb := range callbacks {
		cb(event)
	}
}

// persist saves the current state to storage if available.
func (s *deviceStore) persist(ctx context.Context) {
	if s.storage == nil {
		return
	}

	// Make a copy of state while holding the lock.
	// Only configuration fields that must survive restart are persisted here.
	// See storage.DeviceState for the full list of persisted fields.
	s.mu.RLock()
	state := &storage.DeviceState{
		ProxyServer:   s.proxyServer,
		ProxyPort:     s.proxyPort,
		ServiceIP:     s.serviceIP,
		SkipReg:       s.skipReg,
		SkipRegReason: s.skipRegReason,
		LbMode:        s.lbMode,
	}
	s.mu.RUnlock()

	// Persist synchronously
	if err := s.storage.SaveDevice(ctx, state); err != nil {
		logger.GetLogger().Warn("Failed to persist device state", "error", err)
	}
}

// SetGnmiHandler sets the gNMI handler for state synchronization.
func (s *deviceStore) SetGnmiHandler(handler gnmi.GnmiHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gnmiHandler = handler
}

// parsePort parses a port number string into a uint16 value.
func parsePort(s string) (uint16, error) {
	port, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port: %w", err)
	}
	return uint16(port), nil
}

// Ensure deviceStore implements Store interface
var _ Store = (*deviceStore)(nil)
