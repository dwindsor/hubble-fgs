//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package udp

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/pawelgaczynski/giouring"
)

const (
	eventTypeRead = iota
	eventTypeWrite
)

func addReadRequest(socket int, ring *giouring.Ring, msg *syscall.Msghdr) {
	sqe := ring.GetSQE()
	sqe.PrepareRecvMsg(socket, msg, 0)
	sqe.UserData = eventTypeRead
	ring.Submit()
}

func addWriteRequest(socket int, ring *giouring.Ring, msg *syscall.Msghdr) {
	sqe := ring.GetSQE()
	sqe.PrepareSendMsg(socket, msg, 0)
	sqe.UserData = eventTypeWrite
	ring.Submit()
}

func udpIouServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		logger.GetLogger().Warn("socket failed")
		panic(err)
	}
	addr := &unix.SockaddrInet4{
		Port: 8000,
		Addr: [4]byte{0, 0, 0, 0},
	}
	err = unix.Bind(fd, addr)
	if err != nil {
		logger.GetLogger().Warn("bind failed")
		panic(err)
	}

	uring := giouring.NewRing()
	err = uring.QueueInit(64, 0)
	if err != nil {
		logger.GetLogger().Warn("QueueInit failed")
		panic(err)
	}

	buffer := make([]byte, 1024)
	iovec := syscall.Iovec{
		Base: &buffer[0],
		Len:  1024,
	}
	clientAddr := syscall.RawSockaddrAny{}
	msg := syscall.Msghdr{
		Name:    (*byte)(unsafe.Pointer(&clientAddr)),
		Namelen: uint32(syscall.SizeofSockaddrAny),
		Iov:     &iovec,
		Iovlen:  1,
	}

	addReadRequest(fd, uring, &msg)
	fmt.Printf("Ready\n")

	for {
		cqe, err := uring.WaitCQE()
		if err != nil {
			logger.GetLogger().Warn("WaitCQE failed")
			panic(err)
		}
		uring.CQESeen(cqe)
		eventType := cqe.UserData
		if cqe.Res < 0 {
			panic(fmt.Errorf("async request failed: %d for event: %d", cqe.Res, eventType))
		}
		switch eventType {
		case eventTypeRead:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty read received!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Read")
			msg.Iov.Len = uint64(cqe.Res)
			addWriteRequest(fd, uring, &msg)
		case eventTypeWrite:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty write sent!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Written")
			addReadRequest(fd, uring, &msg)
		}
	}
}
