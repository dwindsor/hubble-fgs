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

func TestDataplaneSocket_Timeout(t *testing.T) {
	sockFile := "/tmp/test_receive_timeout.sock"
	timeout := 500 * time.Millisecond

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

	// Start a goroutine to handle incoming connections
	go func() {
		// Accept connection on the server side
		serverConn, err := listener.Accept()
		if err != nil {
			t.Errorf("Failed to accept connection: %v", err)
			return
		}
		defer serverConn.Close()

		encoder := json.NewEncoder(serverConn)

		// Create a mock response
		response := ControlResponse{ReturnCode: SUCCESS, Data: json.RawMessage(`{"key":"value","num":42}`)}

		// Simulate delay
		time.Sleep(1 * time.Second)

		// Send the mock response back to the client
		err = encoder.Encode(response)
		if err != nil {
			t.Error(err)
			return
		}
	}()

	// Test receiving with timeout
	_, err = dpSocket.Receive()
	if err == nil {
		t.Error("Expected error, got nil")
	}
}
