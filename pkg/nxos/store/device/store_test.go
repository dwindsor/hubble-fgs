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
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"

	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/mock"
	"github.com/isovalent/hubble-fgs/pkg/nxos/gnmi/paths"
)

func makeStringUpdate(s string) *gnmiproto.Update {
	return &gnmiproto.Update{
		Val: &gnmiproto.TypedValue{
			Value: &gnmiproto.TypedValue_StringVal{StringVal: s},
		},
	}
}

func TestStore_SetGnmiHandler(t *testing.T) {
	handler := mock.NewHandler()
	cs := NewStore(context.Background())

	cs.SetGnmiHandler(handler)

	// Verify handler is set by checking that gNMI-dependent operations work
	ctx := context.Background()
	cs.SetAdmissionStatus(ctx, CommonStateSuccess, "")
	cs.SetConnectionStatus(ctx, CommonStateSuccess, "")

	if cs.AdmissionStatus() != CommonStateSuccess {
		t.Errorf("expected admission status success, got %v", cs.AdmissionStatus())
	}
}

func TestStore_HandleGnmiNotification_ConnToken(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate a connToken notification
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreConnToken,
		makeStringUpdate("test-token-value"),
		false,
	)

	token := cs.Token()
	if token != "test-token-value" {
		t.Errorf("expected token 'test-token-value', got %q", token)
	}
}

func TestStore_HandleGnmiNotification_Delete(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Set proxy config first
	cs.SetProxyServer(ctx, "proxy.example.com")
	cs.SetProxyPort(ctx, 8080)
	if cs.ProxyServer() != "proxy.example.com" {
		t.Fatal("proxy server not set")
	}

	// Simulate a proxy server delete notification
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreProxyServer,
		&gnmiproto.Update{},
		true,
	)

	if cs.ProxyServer() != "" {
		t.Errorf("expected proxy server cleared after delete, got %q", cs.ProxyServer())
	}

	// Simulate a proxy port delete notification
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreProxyPort,
		&gnmiproto.Update{},
		true,
	)

	if cs.ProxyPort() != 0 {
		t.Errorf("expected proxy port cleared after delete, got %d", cs.ProxyPort())
	}
}

func TestStore_HandleGnmiNotification_AgentSrcIntfAddr(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreServiceIP,
		makeStringUpdate("10.0.0.1"),
		false,
	)

	if cs.ServiceIP() != "10.0.0.1" {
		t.Errorf("expected service IP '10.0.0.1', got %q", cs.ServiceIP())
	}
}

func TestStore_HandleGnmiNotification_SerialNumber(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate a serial number leaf notification (DeviceStoreSerialNumber = .../serNum)
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreSerialNumber,
		makeStringUpdate("FDO99999999"),
		false,
	)

	if cs.SerialNumber() != "FDO99999999" {
		t.Errorf("expected serial 'FDO99999999', got %q", cs.SerialNumber())
	}
}

func TestStore_HandleGnmiNotification_ChassisItems(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate a chassis notification with nested structure (DeviceStoreSupervisorType = .../supslot-items)
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreSupervisorType,
		makeStringUpdate(`{"SupCSlot-list": [{"id": "1", "sup-items": {"model": "N9K-TEST", "swVer": "10.5(1)"}}]}`),
		false,
	)

	if cs.Model() != "N9K-TEST" {
		t.Errorf("expected model 'N9K-TEST', got %q", cs.Model())
	}
	if cs.SoftwareVersion() != "10.5(1)" {
		t.Errorf("expected software version '10.5(1)', got %q", cs.SoftwareVersion())
	}
}

// Note: Tests for HandleGnmiNotification_AdmissionStatus and HandleGnmiNotification_ConnectionStatus
// have been removed because these are AGW-OWNED paths. NX-OS never writes to ext-items paths,
// so we don't subscribe to or handle notifications for them.

func TestStore_HandleGnmiNotification_InService(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Set in-service to true
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreInService,
		makeStringUpdate("in-service"),
		false,
	)

	if !cs.IsInService() {
		t.Error("expected IsInService true after operState=in-service notification")
	}

	// Set in-service to false
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreInService,
		makeStringUpdate("out-of-service"),
		false,
	)

	if cs.IsInService() {
		t.Error("expected IsInService false after operState=out-of-service notification")
	}
}

func TestStore_HandleGnmiNotification_Model(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreModel,
		makeStringUpdate("N9K-C9364C-GX"),
		false,
	)

	if cs.Model() != "N9K-C9364C-GX" {
		t.Errorf("expected model 'N9K-C9364C-GX', got %q", cs.Model())
	}
}

func TestStore_HandleGnmiNotification_ProxyServer(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate proxy server update
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreProxyServer,
		makeStringUpdate("proxy.example.com"),
		false,
	)

	if cs.ProxyServer() != "proxy.example.com" {
		t.Errorf("expected proxy server 'proxy.example.com', got %q", cs.ProxyServer())
	}
}

func TestStore_HandleGnmiNotification_ProxyPort(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate proxy port update
	cs.HandleGnmiNotification(
		ctx,
		paths.DeviceStoreProxyPort,
		&gnmiproto.Update{
			Val: &gnmiproto.TypedValue{
				Value: &gnmiproto.TypedValue_UintVal{UintVal: 8080},
			},
		},
		false,
	)

	if cs.ProxyPort() != 8080 {
		t.Errorf("expected proxy port 8080, got %d", cs.ProxyPort())
	}
}

func TestStore_ProxyAddress(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Empty when no proxy configured
	if cs.ProxyAddress() != "" {
		t.Errorf("expected empty proxy address, got %q", cs.ProxyAddress())
	}

	// Server only, no port
	cs.SetProxyServer(ctx, "proxy.example.com")
	if cs.ProxyAddress() != "proxy.example.com" {
		t.Errorf("expected 'proxy.example.com', got %q", cs.ProxyAddress())
	}

	// Server and port combined
	cs.SetProxyPort(ctx, 8080)
	if cs.ProxyAddress() != "proxy.example.com:8080" {
		t.Errorf("expected 'proxy.example.com:8080', got %q", cs.ProxyAddress())
	}
}

func TestStore_SetAdmissionAndConnectionStatus(t *testing.T) {
	handler := mock.NewHandler()
	ctx := context.Background()
	cs := NewStore(ctx, WithGnmiHandler(handler))

	cs.SetAdmissionStatus(ctx, CommonStateSuccess, "")
	cs.SetConnectionStatus(ctx, CommonStateSuccess, "")

	if cs.AdmissionStatus() != CommonStateSuccess {
		t.Errorf("expected admission status success, got %v", cs.AdmissionStatus())
	}
	if cs.ConnectionStatus() != CommonStateSuccess {
		t.Errorf("expected connection status success, got %v", cs.ConnectionStatus())
	}
}

func TestStore_SetControllerEndpointAndPort(t *testing.T) {
	handler := mock.NewHandler()
	ctx := context.Background()
	cs := NewStore(ctx, WithGnmiHandler(handler))

	cs.SetControllerEndpoint(ctx, "device.example.com")
	cs.SetControllerPort(ctx, 443)

	if cs.ControllerEndpoint() != "device.example.com" {
		t.Errorf("expected controller endpoint 'device.example.com', got %q", cs.ControllerEndpoint())
	}
	if cs.ControllerPort() != 443 {
		t.Errorf("expected controller port 443, got %d", cs.ControllerPort())
	}

	// Verify gNMI SET was called
	strs, err := handler.Get(ctx, paths.DeviceStoreControllerEndpoint)
	if err != nil {
		t.Fatalf("failed to get controller endpoint from mock: %v", err)
	}
	if len(strs) == 0 {
		t.Fatal("expected data at DeviceStoreControllerEndpoint after SetControllerEndpoint")
	}
}

func TestStore_SetSystemState(t *testing.T) {
	handler := mock.NewHandler()
	ctx := context.Background()
	cs := NewStore(ctx, WithGnmiHandler(handler))

	cs.SetSystemState(ctx, 0xFF)

	// Verify gNMI SET was called
	strs, err := handler.Get(ctx, paths.DeviceStoreSystemState)
	if err != nil {
		t.Fatalf("failed to get system state from mock: %v", err)
	}
	if len(strs) == 0 {
		t.Fatal("expected data at DeviceStoreSystemState after SetSystemState")
	}
}

func TestStore_IsSkipReg_ReloadReadOnce(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Set skipReg with reload
	cs.SetSkipReg(ctx, true, "some reason")

	// Manually set reload to verify read-once behavior
	cs.(*deviceStore).mu.Lock()
	cs.(*deviceStore).reload = true
	cs.(*deviceStore).mu.Unlock()

	// First call: should return reload=true and clear it
	skipReg, reload, reason := cs.IsSkipReg()
	if !skipReg {
		t.Error("expected skipReg true")
	}
	if !reload {
		t.Error("expected reload true on first call")
	}
	if reason != "some reason" {
		t.Errorf("expected reason 'some reason', got %q", reason)
	}

	// Second call: reload should now be false (read-once semantics)
	_, reload2, _ := cs.IsSkipReg()
	if reload2 {
		t.Error("expected reload false on second call (read-once semantics)")
	}
}

func TestStore_SetToken_ClearsSkipRegOnK8sAuthFailure(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Simulate a K8s auth failure setting skipReg
	cs.SetSkipReg(ctx, true, regFailK8sAuth)

	skipReg, _, reason := cs.IsSkipReg()
	if !skipReg {
		t.Fatal("expected skipReg to be set")
	}
	if reason != regFailK8sAuth {
		t.Fatalf("expected reason %q, got %q", regFailK8sAuth, reason)
	}

	// Now set a new token — should auto-clear skipReg and set reload
	_, err := cs.(*deviceStore).SetToken(ctx, "new-valid-token")
	if err != nil {
		t.Fatalf("unexpected error from SetToken: %v", err)
	}

	skipReg2, reload, reason2 := cs.IsSkipReg()
	if skipReg2 {
		t.Error("expected skipReg to be cleared after token update")
	}
	if !reload {
		t.Error("expected reload to be set after token update cleared skipReg")
	}
	if reason2 != "" {
		t.Errorf("expected empty reason after skipReg cleared, got %q", reason2)
	}
}

func TestStore_SetToken_DoesNotClearSkipRegOnOtherReason(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// Set skipReg with a different reason
	cs.SetSkipReg(ctx, true, "other failure reason")

	// Set a new token
	cs.(*deviceStore).SetToken(ctx, "some-token") //nolint:errcheck

	// skipReg should NOT be cleared (only K8sAuth reason triggers auto-clear)
	skipReg, reload, _ := cs.IsSkipReg()
	if !skipReg {
		t.Error("expected skipReg to remain set for non-K8sAuth reason")
	}
	if reload {
		t.Error("expected reload to remain false for non-K8sAuth reason")
	}
}

func TestStore_InServiceState_Initial(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	if cs.InServiceState() != "" {
		t.Errorf("expected empty InServiceState initially, got %q", cs.InServiceState())
	}
	if cs.IsInService() {
		t.Error("expected IsInService false initially")
	}
}

func TestStore_SetInService_String(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	cs.SetInService(ctx, "in-service")
	if cs.InServiceState() != "in-service" {
		t.Errorf("expected InServiceState 'in-service', got %q", cs.InServiceState())
	}
	if !cs.IsInService() {
		t.Error("expected IsInService true after 'in-service'")
	}

	cs.SetInService(ctx, "out-of-service")
	if cs.InServiceState() != "out-of-service" {
		t.Errorf("expected InServiceState 'out-of-service', got %q", cs.InServiceState())
	}
	if cs.IsInService() {
		t.Error("expected IsInService false after 'out-of-service'")
	}
}

func TestStore_SetInService_EmitEvent(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	var received []Event
	cs.Watch(func(e Event) {
		received = append(received, e)
	})

	cs.SetInService(ctx, "in-service")
	cs.SetInService(ctx, "in-service") // no-op, no duplicate event
	cs.SetInService(ctx, "out-of-service")

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}
	if received[0].Type != EventInServiceChanged || received[0].Status != "in-service" {
		t.Errorf("expected EventInServiceChanged 'in-service', got type=%q status=%q", received[0].Type, received[0].Status)
	}
	if received[1].Type != EventInServiceChanged || received[1].Status != "out-of-service" {
		t.Errorf("expected EventInServiceChanged 'out-of-service', got type=%q status=%q", received[1].Type, received[1].Status)
	}
}

func TestStore_HandleGnmiNotification_InService_RawString(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// "in-service" sets state to "in-service"
	cs.HandleGnmiNotification(ctx, paths.DeviceStoreInService, makeStringUpdate("in-service"), false)
	if cs.InServiceState() != "in-service" {
		t.Errorf("expected 'in-service', got %q", cs.InServiceState())
	}

	// "out-of-service" sets state to "out-of-service"
	cs.HandleGnmiNotification(ctx, paths.DeviceStoreInService, makeStringUpdate("out-of-service"), false)
	if cs.InServiceState() != "out-of-service" {
		t.Errorf("expected 'out-of-service', got %q", cs.InServiceState())
	}
}

func TestStore_SettersNilHandler(t *testing.T) {
	ctx := context.Background()
	cs := NewStore(ctx)

	// All setters should work without panicking when gnmiHandler is nil
	cs.SetAdmissionStatus(ctx, CommonStateSuccess, "")
	cs.SetConnectionStatus(ctx, CommonStateSuccess, "")
	cs.SetControllerEndpoint(ctx, "test.example.com")
	cs.SetControllerPort(ctx, 443)
	cs.SetControllerVersion(ctx, "1.0.0")
	cs.SetSystemState(ctx, 0)

	if cs.AdmissionStatus() != CommonStateSuccess {
		t.Errorf("expected admission status success, got %v", cs.AdmissionStatus())
	}
	if cs.ControllerEndpoint() != "test.example.com" {
		t.Errorf("expected controller endpoint 'test.example.com', got %q", cs.ControllerEndpoint())
	}
}
