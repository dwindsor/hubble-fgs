package socket

import (
	"encoding/json"
	"net"
	"os"
	"testing"
	"time"
)

func TestDataplaneSocket_Connect(t *testing.T) {
	sockFile := "/tmp/test.sock"
	timeout := 2 * time.Second

	// Create a Unix socket listener for testing
	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		t.Fatalf("Failed to create Unix socket listener: %v", err)
	}
	defer listener.Close()
	defer os.Remove(sockFile)

	dpSocket := NewDataplaneSocket(sockFile, timeout)

	// Test successful connection
	err = dpSocket.Connect()
	if err != nil {
		t.Fatalf("Expected successful connection, got error: %v", err)
	}
	defer dpSocket.Close()
}

func TestDataplaneSocket_SendReceive(t *testing.T) {
	sockFile := "/tmp/test_send_receive.sock"
	timeout := 2 * time.Second

	// Recover from fatal tests
	os.Remove(sockFile)
	// Create a Unix socket listener for testing
	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		t.Fatalf("Failed to create Unix socket listener: %v", err)
	}
	defer listener.Close()
	defer os.Remove(sockFile)

	dpSocket := NewDataplaneSocket(sockFile, timeout)

	// Test successful connection
	err = dpSocket.Connect()
	if err != nil {
		t.Fatalf("Expected successful connection, got error: %v", err)
	}
	defer dpSocket.Close()

	// Accept connection on the server side
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}
	defer serverConn.Close()

	// Test sending a message
	msg := &ControlMessage{Command: 0, Type: 0, Data: json.RawMessage(`{"key":"value","num":42}`)}
	err = dpSocket.Send(msg)
	if err != nil {
		t.Fatalf("Expected successful send, got error: %v", err)
	}

	// Receive the message on the server side
	var receivedMsg ControlMessage
	decoder := json.NewDecoder(serverConn)
	err = decoder.Decode(&receivedMsg)
	if err != nil {
		t.Fatalf("Failed to decode message: %v", err)
	}

	if msg.Command != receivedMsg.Command || msg.Type != receivedMsg.Type || string(msg.Data) != string(receivedMsg.Data) {
		t.Fatalf("Expected message data %v, got %v", string(msg.Data), string(receivedMsg.Data))
	}

	// Test receiving a response
	response := ControlResponse{ReturnCode: NOT_SUPPORTED, Data: json.RawMessage(`{"key":"value","num":42}`)}
	encoder := json.NewEncoder(serverConn)
	err = encoder.Encode(response)
	if err != nil {
		t.Fatalf("Failed to encode response: %v", err)
	}

	receivedResponse, err := dpSocket.Receive()
	if err != nil {
		t.Fatalf("Expected successful receive, got error: %v", err)
	}

	if response.ReturnCode != receivedResponse.ReturnCode || string(response.Data) != string(receivedResponse.Data) {
		t.Fatalf("Expected response %s, got %s", string(response.Data), string(receivedResponse.Data))
	}
}

func TestDataplaneSocket_SendNotConnected(t *testing.T) {
	dpSocket := NewDataplaneSocket("/tmp/nonexistent.sock", 2*time.Second)

	// Test sending without connecting first
	msg := &ControlMessage{Command: 0, Type: 0, Data: json.RawMessage(`{}`)}
	err := dpSocket.Send(msg)
	if err == nil {
		t.Fatal("Expected error when sending on unconnected socket")
	}
	if err.Error() != "socket not connected" {
		t.Fatalf("Expected 'socket not connected' error, got: %v", err)
	}
}

func TestDataplaneSocket_ReceiveNotConnected(t *testing.T) {
	dpSocket := NewDataplaneSocket("/tmp/nonexistent.sock", 2*time.Second)

	// Test receiving without connecting first
	_, err := dpSocket.Receive()
	if err == nil {
		t.Fatal("Expected error when receiving on unconnected socket")
	}
	if err.Error() != "socket not connected" {
		t.Fatalf("Expected 'socket not connected' error, got: %v", err)
	}
}

func TestDataplaneSocket_CloseNotConnected(t *testing.T) {
	dpSocket := NewDataplaneSocket("/tmp/nonexistent.sock", 2*time.Second)

	// Test closing without connecting first - should not panic
	err := dpSocket.Close()
	if err != nil {
		t.Fatalf("Expected no error when closing unconnected socket, got: %v", err)
	}
}

func TestDataplaneSocket_CloseMultipleTimes(t *testing.T) {
	sockFile := "/tmp/test_close_multiple.sock"
	timeout := 2 * time.Second

	os.Remove(sockFile)
	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		t.Fatalf("Failed to create Unix socket listener: %v", err)
	}
	defer listener.Close()
	defer os.Remove(sockFile)

	dpSocket := NewDataplaneSocket(sockFile, timeout)

	err = dpSocket.Connect()
	if err != nil {
		t.Fatalf("Expected successful connection, got error: %v", err)
	}

	// Close multiple times - should not panic
	err = dpSocket.Close()
	if err != nil {
		t.Fatalf("First close failed: %v", err)
	}

	err = dpSocket.Close()
	if err != nil {
		t.Fatalf("Second close should succeed (no-op), got: %v", err)
	}
}

func TestDataplaneSocket_SendReceiveAfterClose(t *testing.T) {
	sockFile := "/tmp/test_after_close.sock"
	timeout := 2 * time.Second

	os.Remove(sockFile)
	listener, err := net.Listen("unix", sockFile)
	if err != nil {
		t.Fatalf("Failed to create Unix socket listener: %v", err)
	}
	defer listener.Close()
	defer os.Remove(sockFile)

	dpSocket := NewDataplaneSocket(sockFile, timeout)

	err = dpSocket.Connect()
	if err != nil {
		t.Fatalf("Expected successful connection, got error: %v", err)
	}

	err = dpSocket.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Send after close should return error
	msg := &ControlMessage{Command: 0, Type: 0, Data: json.RawMessage(`{}`)}
	err = dpSocket.Send(msg)
	if err == nil {
		t.Fatal("Expected error when sending after close")
	}

	// Receive after close should return error
	_, err = dpSocket.Receive()
	if err == nil {
		t.Fatal("Expected error when receiving after close")
	}
}
