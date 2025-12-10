package ipc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/tetragon/pkg/logger"
)

type MessageData struct {
	Args  []string          `json:"args"`
	Flags map[string]string `json:"flags"`
}

type controlMessage struct {
	Command int         `json:"command"`
	Data    MessageData `json:"data"`
}

type ReturnCode struct {
	ReturnCode string `json:"returnCode"`
	Data       string `json:"data"`
}

func PrintResponse(ret *ReturnCode, raw_json bool) {
	if raw_json {
		// Check if Data is already valid JSON
		var dataJson json.RawMessage
		err := json.Unmarshal([]byte(ret.Data), &dataJson)
		if err == nil {
			// Data is valid json, construct response with raw json (compact, no indentation)
			response := map[string]interface{}{
				"returnCode": ret.ReturnCode,
				"data":       dataJson,
			}
			resp, err := json.Marshal(response)
			if err != nil {
				fmt.Println("Error: Failed to print JSON")
			} else {
				fmt.Printf("%s\n", resp)
			}
		} else {
			// Data is not JSON, marshal normally
			resp, err := json.Marshal(ret)
			if err != nil {
				fmt.Println("Error: Failed to print JSON")
			} else {
				fmt.Printf("%s\n", resp)
			}
		}
	} else {
		fmt.Printf("Client got: %s\n", ret.ReturnCode)
		fmt.Printf("Data: %s\n", ret.Data)
	}
}

func SendCmd(_ context.Context, sock_file string, cmd int, data MessageData) (*ReturnCode, error) {
	txJson := &controlMessage{
		Command: cmd,
		Data:    data,
	}

	ret, err := send(sock_file, txJson)
	if err != nil {
		logger.GetLogger().Error("Failed to send command", logfields.Error, err, "json", txJson)
		return nil, err
	}
	return ret, nil
}

func SendCmdTimeout(ctx context.Context, sock_file string, cmd int, data MessageData, timeout time.Duration) (*ReturnCode, error) {
	txJson := &controlMessage{
		Command: cmd,
		Data:    data,
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, _ := net.ResolveUnixAddr("unix", sock_file)
	dialer := net.Dialer{}
	conn, err := dialer.Dial("unix", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctxWithTimeout.Deadline()
	conn.SetDeadline(deadline)

	encode := json.NewEncoder(conn)
	decode := json.NewDecoder(conn)

	err = encode.Encode(txJson)
	if err != nil {
		return nil, err
	}

	var rxJson ReturnCode
	err = decode.Decode(&rxJson)
	if err != nil {
		return nil, err
	}
	return &rxJson, nil
}

func SendReceieveMsgs(ctx context.Context, sock_file string, cmd int, data MessageData, timeout time.Duration, num int) ([]map[string]interface{}, error) {
	txJson := &controlMessage{
		Command: cmd,
		Data:    data,
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, _ := net.ResolveUnixAddr("unix", sock_file)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctxWithTimeout.Deadline()
	conn.SetDeadline(deadline)

	encode := json.NewEncoder(conn)
	decode := json.NewDecoder(conn)

	err = encode.Encode(txJson)
	if err != nil {
		return nil, err
	}

	var rxJsons []map[string]interface{}
	for i := 0; i < num; i++ {
		var rxJson map[string]interface{}
		err = decode.Decode(&rxJson)
		if err != nil {
			logger.GetLogger().Error("Failed to receive message", logfields.Error, err, "msg", i)
			continue
		}
		rxJsons = append(rxJsons, rxJson)
	}
	return rxJsons, nil
}

func ReceiveMsgs(ctx context.Context, sock_file string, timeout time.Duration, num int) ([]map[string]interface{}, error) {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, _ := net.ResolveUnixAddr("unix", sock_file)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctxWithTimeout.Deadline()
	conn.SetDeadline(deadline)

	decode := json.NewDecoder(conn)

	var rxJsons []map[string]interface{}
	for i := 0; i < num; i++ {
		var rxJson map[string]interface{}
		err = decode.Decode(&rxJson)
		if err != nil {
			logger.GetLogger().Error("Failed to receive message", logfields.Error, err, "msg", i)
			continue
		}
		rxJsons = append(rxJsons, rxJson)
	}
	return rxJsons, nil
}

func ReceiveMsg(ctx context.Context, sock_file string, timeout time.Duration) (map[string]interface{}, error) {
	ctxWithTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, _ := net.ResolveUnixAddr("unix", sock_file)
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", addr.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline, _ := ctxWithTimeout.Deadline()
	conn.SetDeadline(deadline)

	decode := json.NewDecoder(conn)
	var rxJson map[string]interface{}
	err = decode.Decode(&rxJson)
	if err != nil {
		logger.GetLogger().Error("Failed to receive message", logfields.Error, err, "msg", rxJson)
		return nil, err
	}
	return rxJson, nil
}

func send(sock_file string, msg *controlMessage) (*ReturnCode, error) {
	addr, _ := net.ResolveUnixAddr("unix", sock_file)
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	encode := json.NewEncoder(conn)
	decode := json.NewDecoder(conn)

	err = encode.Encode(msg)
	if err != nil {
		return nil, err
	}

	var rxJson ReturnCode
	err = decode.Decode(&rxJson)
	if err != nil {
		return &rxJson, err
	}
	return &rxJson, nil
}
