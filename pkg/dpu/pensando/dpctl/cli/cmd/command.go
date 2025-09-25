//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package cmd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os/signal"
	"syscall"

	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/proto"

	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dp"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/dpctl/cli/utils"
	"github.com/isovalent/hubble-fgs/pkg/dpu/pensando/pds"

	"os"
)

var dpUdsPath string = "/var/run/pds_svc_server_dp_app.sock"
var CmdSocket string
var transport string

type Transport int

const (
	AGENT_TRANSPORT_NONE Transport = 0
	AGENT_TRANSPORT_GRPC Transport = 1
	AGENT_TRANSPORT_UDS  Transport = 2
	UDS_MSG_HDR_SIZE     int       = 8
)

var AgentTransport Transport

// function helper function to get valid uds socket
// return    err     Error
//
//	CmdSocket Valid socket path
func FindSocketPath() (error, string) {
	return nil, dpUdsPath
}

// function to handle commands over unix domain sockets
// param[in] cmdReq  Service request message to be sent
// return    cmdResp Service response message
//
//	err     Error
func HandleCommand(cmdReq *dp.ServiceRequestMessage,
	socket string) (*dp.ServiceResponseMessage, error) {
	// marshall cmdCtxt
	iovec, err := proto.Marshal(cmdReq)
	if err != nil {
		fmt.Printf("Marshal command failed with error %v\n", err)
		return nil, err
	}

	// send over UDS
	resp, err := utils.CmdSendRecv(socket, iovec, int(os.Stdout.Fd()))
	if err != nil {
		fmt.Printf("Command send operation failed with error %v\n", err)
		return nil, err
	}

	// unmarshal response
	cmdResp := &dp.ServiceResponseMessage{}
	if resp != nil {
		err = proto.Unmarshal(resp, cmdResp)
		if err != nil {
			fmt.Printf("Command failed with %v error\n", err)
			return nil, err
		}
	}
	return cmdResp, nil
}

// function to handle configs over unix domain sockets
// param[in] cfgReq  Service request message to be sent
// param[in] socket  Socket address (optional)
// return    cfgResp Service response message
//
//	err     Error
func HandleConfig(cfgReq *dp.ServiceRequestMessage, socket ...string) (*dp.ServiceResponseMessage, error) {
	// marshall cmdCtxt
	iovec, err := proto.Marshal(cfgReq)
	if err != nil {
		fmt.Printf("Marshall command failed with error %v\n", err)
		return nil, err
	}

	// send over UDS
	if len(socket) != 0 {
		CmdSocket = socket[0]
	} else {
		err, CmdSocket = FindSocketPath()
		if err != nil {
			fmt.Printf("Error: Cannot find valid socket path %v\n", err)
			return nil, err
		}
	}

	resp, err := utils.CmdSendRecv(CmdSocket, iovec, -1)
	if err != nil {
		fmt.Printf("Command send operation failed with error %v\n", err)
		return nil, err
	}

	// unmarshal response
	if resp != nil {
		cmdResp := &dp.ServiceResponseMessage{}
		err = proto.Unmarshal(resp, cmdResp)
		if err != nil {
			fmt.Printf("Command failed with %v error\n", err)
			return nil, err
		}
		return cmdResp, nil
	}
	return nil, nil
}

// function to handle command service request message
// param[in]  cmd       command
// param[in]  req       request
// param[out] resp      response
// return     err       Error
func HandleSvcReqCommandMsg(op dp.CommandOp,
	req proto.Message) (*dp.ServiceResponseMessage, error) {
	var reqMsg *types.Any
	var err error

	if req != nil {
		reqMsg, err = types.MarshalAny(req)
		if err != nil {
			fmt.Printf("HandleSvcReqCommandMsg: Marshal req failed with %v error\n", err)
			return nil, err
		}
	} else {
		reqMsg = nil
	}

	command := &dp.CommandMessage{
		Command:    op,
		CommandMsg: reqMsg,
	}

	cmdReqMsg, err := types.MarshalAny(command)
	if err != nil {
		fmt.Printf("HandleSvcReqCommandMsg: Marshal command failed with %v error\n", err)
		return nil, err
	}

	cmdReq := &dp.ServiceRequestMessage{
		ConfigOp:  dp.ServiceRequestOp_SERVICE_OP_NONE,
		ConfigMsg: cmdReqMsg,
	}

	err, CmdSocket = FindSocketPath()
	if err != nil {
		fmt.Printf("Error: Cannot find valid socket path\n")
		return nil, err
	}

	// handle command
	return HandleCommand(cmdReq, CmdSocket)
}

// function to handle config service request message
// param[in]  req       request
// param[in]  op        operation (crud)
// param[in]  socket    socket address (optional)
// param[out] resp      response
// return     err       Error
func HandleSvcReqConfigMsg(op dp.ServiceRequestOp,
	req proto.Message, resp proto.Message, socket ...string) error {
	reqMsg, err := types.MarshalAny(req)
	if err != nil {
		fmt.Printf("Command failed with %v error\n", err)
		return err
	}

	cmdReq := &dp.ServiceRequestMessage{
		ConfigOp:  op,
		ConfigMsg: reqMsg,
	}

	var cmdResp *dp.ServiceResponseMessage
	// handle config
	if len(socket) != 0 {
		cmdResp, err = HandleConfig(cmdReq, socket[0])
	} else {
		cmdResp, err = HandleConfig(cmdReq)
	}
	if err != nil {
		return err
	}

	if cmdResp == nil {
		return fmt.Errorf("Command failed to get response\n")
	}
	if cmdResp.ApiStatus != pds.ApiStatus_API_STATUS_OK {
		fmt.Printf("Command failed with %v error\n", cmdResp.ApiStatus)
		return fmt.Errorf("Command failed with %v error\n", cmdResp.ApiStatus)
	}
	// MK - I could not get my response to unmarshal.  Since this code doesn't do anything
	// functionally, I commented it out.
	// anyResp := cmdResp.GetResponse()

	// if resp != nil {
	// 	err = types.UnmarshalAny(anyResp, resp)
	// 	if err != nil {
	// 		fmt.Printf("UnmarshalAny returned an error\n.")
	// 		fmt.Printf("Command failed with %v error\n", err)
	// 		return err
	// 	}
	// }

	return err
}

// function to handle config service request message with streaming response
// param[in]  dataChannel       channel to send responses to
// param[in]  ctrlChannel       channel to indicate response has been processed
// param[in]  req               request
// param[in]  op                operation (crud)
// param[in]  socket            uds socket address to connect to(optional)
// return     err               Error
func HandleSvcReqConfigMsgStreaming(dataChannel chan *types.Any,
	ctrlChannel chan bool,
	op dp.ServiceRequestOp,
	req proto.Message, socket ...string) error {
	reqMsg, err := types.MarshalAny(req)
	if err != nil {
		fmt.Printf("Error: Marshal command failed with error %v\n", err)
		dataChannel <- nil
		return err
	}

	// create service request message
	cmdReq := &dp.ServiceRequestMessage{
		ConfigOp:  op,
		ConfigMsg: reqMsg,
	}

	// marshall service request message
	iovec, err := proto.Marshal(cmdReq)
	if err != nil {
		fmt.Printf("Error: Marshal command failed with error %v\n", err)
		dataChannel <- nil
		return err
	}

	// senlect socket path to send request to
	if len(socket) != 0 {
		CmdSocket = socket[0]
	} else {
		err, CmdSocket = FindSocketPath()
		if err != nil {
			fmt.Printf("Error: Cannot find valid socket path %v\n", err)
			dataChannel <- nil
			return err
		}
	}

	// connect to UDS socket
	c, err := net.Dial("unix", CmdSocket)
	if err != nil {
		fmt.Printf("Error: Connect to unix domain socket with error %v\n", err)
		dataChannel <- nil
		return err
	}
	defer c.Close()

	udsConn := c.(*net.UnixConn)
	udsFile, err := udsConn.File()
	if err != nil {
		fmt.Printf("Error: Connect to unix domain socket with error %v\n", err)
		dataChannel <- nil
		return err
	}
	sock := int(udsFile.Fd())
	defer udsFile.Close()

	// send the request
	err = syscall.Sendmsg(sock, iovec, nil, nil, 0)
	if err != nil {
		fmt.Printf("Error: Sendmsg failed with error %v\n", err)
		dataChannel <- nil
		return err
	}

	// handle interrupts
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)
	go func(f *os.File) {
		<-signalChannel // Wait for interrupt signal
		f.Close()
		os.Exit(0)
	}(udsFile)

	// As we receive responses, we append them to rcvMsg. Once we have
	// a complete message we will remove it from rcvMsg and save it in
	// currMsg to be processed
	var rcvMsg bytes.Buffer
	var currMsg bytes.Buffer
	byteResp := make([]byte, 20480)
	for {
		n, _, _, _, err := syscall.Recvmsg(sock, byteResp, nil, 0)
		if err != nil {
			fmt.Printf("Error: Recvmsg failed with error %v\n", err)
			dataChannel <- nil
			return err
		}
		if n == 0 {
			// we are not receiving any more data, so we need
			// to exhaust what we have already received
			if rcvMsg.Len() == 0 {
				dataChannel <- nil
				break
			}
		} else {
			// append to message already read
			rcvMsg.Write(byteResp[:n])
			if n < UDS_MSG_HDR_SIZE {
				// need enough bytes to read the header at least
				continue
			}
		}
		// read uds msg hdr specifying size of message
		msg := rcvMsg.Bytes()
		msgLen := int(binary.LittleEndian.Uint64(msg[:UDS_MSG_HDR_SIZE]))
		// check if entire message has been received
		if msgLen > rcvMsg.Len()-UDS_MSG_HDR_SIZE {
			// entire message is not received
			continue
		} else if msgLen < rcvMsg.Len()-UDS_MSG_HDR_SIZE {
			// we received more than the current message
			currMsg.Write(msg[UDS_MSG_HDR_SIZE : msgLen+UDS_MSG_HDR_SIZE])
			// remove the current message from rcvMsg
			rcvMsg.Reset()
			// save remaining message in rcvMsg
			rcvMsg.Write(msg[msgLen+UDS_MSG_HDR_SIZE:])
		} else {
			// we received exactly one message
			currMsg.Write(msg[UDS_MSG_HDR_SIZE:])
			rcvMsg.Reset()
		}

		// received complete message
		cmdResp := &dp.ServiceResponseMessage{}
		err = proto.Unmarshal(currMsg.Bytes(), cmdResp)
		if err != nil {
			fmt.Printf("Error: Unable to unmarshal received message\n")
			dataChannel <- nil
			return err
		}
		// send any message from response to data channel
		dataChannel <- cmdResp.GetResponse()
		// wait to see if message has been processed
		<-ctrlChannel
		// processed current message so go ahead and reset
		currMsg.Reset()
	}
	return nil
}

func GetAgentTransport(cmd *cobra.Command) (Transport, error) {
	if cmd != nil && cmd.Flags().Changed("transport") {
		if transport == "uds" {
			return AGENT_TRANSPORT_UDS, nil
		} else if transport == "grpc" {
			return AGENT_TRANSPORT_GRPC, nil
		} else {
			return AGENT_TRANSPORT_NONE,
				errors.New("Transport specified is invalid, refer help string")
		}
	} else {
		val, present := os.LookupEnv("PDS_AGENT_TRANSPORT")
		if present != true {
			return AGENT_TRANSPORT_GRPC, nil
		} else {
			if val == "uds" {
				return AGENT_TRANSPORT_UDS, nil
			} else if val == "grpc" {
				return AGENT_TRANSPORT_GRPC, nil
			} else {
				return AGENT_TRANSPORT_NONE,
					errors.New("Environment variable PDS_AGENT_TRANSPORT is invalid. Should be uds or grpc")
			}
		}
	}
	return AGENT_TRANSPORT_NONE, errors.New("Invalid transport")
}
