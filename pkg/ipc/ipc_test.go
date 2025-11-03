package ipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"
)

var GlobCtx context.Context

func init() {
	// Setting up logger and context
	GlobCtx = context.Background()
}

func TestSendCmd(t *testing.T) {
	// Start a mock server
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/mock.sock", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Start a goroutine to handle incoming connections
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		decode := json.NewDecoder(conn)
		encode := json.NewEncoder(conn)

		// Read the control message from the client
		var txJson controlMessage
		err = decode.Decode(&txJson)
		if err != nil {
			t.Error(err)
			return
		}

		if txJson.Command != 123 {
			t.Errorf("Expected command to be 123, got %d", txJson.Command)
		}
		if len(txJson.Data.Args) != 1 || txJson.Data.Args[0] != "test-arg" {
			t.Errorf("Expected data.args to be ['test-arg'], got %v", txJson.Data.Args)
		}
		if txJson.Data.Flags["key"] != "value" {
			t.Errorf("Expected data.flags['key'] to be 'value', got '%s'", txJson.Data.Flags["key"])
		}

		// Create a mock response
		rxJson := ReturnCode{
			ReturnCode: "success",
			Data:       "mock data",
		}

		// Send the mock response back to the client
		err = encode.Encode(rxJson)
		if err != nil {
			t.Error(err)
			return
		}
	}()

	// Call the SendCommand function with the mock server address
	sockFile := "/tmp/mock.sock"
	cmd := 123
	msgData := MessageData{
		Args:  []string{"test-arg"},
		Flags: map[string]string{"key": "value"},
	}
	ret, err := SendCmd(GlobCtx, sockFile, cmd, msgData)
	if err != nil {
		t.Fatal(err)
	}
	if ret.ReturnCode != "success" {
		t.Errorf("Expected ReturnCode to be 'success', got '%s'", ret.ReturnCode)
	}
	if ret.Data != "mock data" {
		t.Errorf("Expected Data to be 'mock data', got '%s'", ret.Data)
	}
}

func TestReceiveMsg(t *testing.T) {
	// Start a mock server
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/mock_receive.sock", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Start a goroutine to handle incoming connections
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		// Create a mock response
		rxJson := map[string]interface{}{
			"returnCode": "success",
			"data":       "mock data",
		}

		// Send the mock response back to the client
		encode := json.NewEncoder(conn)
		err = encode.Encode(rxJson)
		if err != nil {
			t.Error(err)
			return
		}

		time.Sleep(2 * time.Second)
	}()

	// Call the ReceiveMsg function with the mock server address
	sockFile := "/tmp/mock_receive.sock"
	timeout := 5 * time.Second
	ret, err := ReceiveMsg(GlobCtx, sockFile, timeout)
	if err != nil {
		t.Fatal(err)
	}
	if ret["returnCode"] != "success" {
		t.Errorf("Expected returnCode to be 'success', got '%s'", ret["returnCode"])
	}
	if ret["data"] != "mock data" {
		t.Errorf("Expected data to be 'mock data', got '%s'", ret["data"])
	}

	// Test timeout
	sockFile = "/tmp/mock_receive.sock"
	timeout = 1 * time.Second
	_, err = ReceiveMsg(GlobCtx, sockFile, timeout)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	} else {
		if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
			t.Errorf("Expected a net.Error with Timeout() == true, got %T: %v", err, err)
		}
	}
}

func TestSendCmdTimeout(t *testing.T) {
	// Start a mock server
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: "/tmp/mock_timeout.sock", Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Start a goroutine to handle incoming connections
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()

		decode := json.NewDecoder(conn)
		encode := json.NewEncoder(conn)

		// Read the control message from the client
		var txJson controlMessage
		err = decode.Decode(&txJson)
		if err != nil {
			t.Error(err)
			return
		}

		if txJson.Command != 123 {
			t.Errorf("Expected command to be 123, got %d", txJson.Command)
		}
		if len(txJson.Data.Args) != 2 || txJson.Data.Args[0] != "arg1" || txJson.Data.Args[1] != "arg2" {
			t.Errorf("Expected data.args to be ['arg1', 'arg2'], got %v", txJson.Data.Args)
		}
		if txJson.Data.Flags["timeout"] != "test" {
			t.Errorf("Expected data.flags['timeout'] to be 'test', got '%s'", txJson.Data.Flags["timeout"])
		}

		// Create a mock response
		rxJson := ReturnCode{
			ReturnCode: "success",
			Data:       "mock data",
		}

		// Simulate delay
		time.Sleep(1 * time.Second)

		// Send the mock response back to the client
		err = encode.Encode(rxJson)
		if err != nil {
			t.Error(err)
			return
		}
	}()

	// Call the SendCmdTimeout function with the mock server address
	sockFile := "/tmp/mock_timeout.sock"
	cmd := 123
	timeout := 2 * time.Second
	msgData := MessageData{
		Args:  []string{"arg1", "arg2"},
		Flags: map[string]string{"timeout": "test"},
	}
	ret, err := SendCmdTimeout(GlobCtx, sockFile, cmd, msgData, timeout)
	if err != nil {
		t.Fatal(err)
	}
	if ret.ReturnCode != "success" {
		t.Errorf("Expected ReturnCode to be 'success', got '%s'", ret.ReturnCode)
	}
	if ret.Data != "mock data" {
		t.Errorf("Expected Data to be 'mock data', got '%s'", ret.Data)
	}

	// Test timeout
	timeout = 500 * time.Millisecond
	_, err = SendCmdTimeout(GlobCtx, sockFile, cmd, msgData, timeout)
	if err == nil {
		t.Error("Expected timeout error, got nil")
	} else {
		if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
			t.Errorf("Expected a net.Error with Timeout() == true, got %T: %v", err, err)
		}
	}
}
