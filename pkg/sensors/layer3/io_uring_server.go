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

package layer3

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/pawelgaczynski/giouring"
)

const (
	eventTypeRead = iota
	eventTypeWrite
	eventTypeAccept
	eventTypeCloseClient
	eventTypeClose
	eventTypeConnect
)

func addAcceptRequest(socket int, ring *giouring.Ring, clientAddr *unix.SockaddrInet4, clientAddrLen *uint32) {
	sqe := ring.GetSQE()
	sqe.PrepareAccept(socket, uintptr(unsafe.Pointer(clientAddr)), uint64(uintptr(unsafe.Pointer(clientAddrLen))), 0)
	sqe.UserData = eventTypeAccept
	ring.Submit()
}

func addConnectRequest(socket int, ring *giouring.Ring, serverAddr *my_sockaddr_in, serverAddrLen uint32) {
	sqe := ring.GetSQE()
	sqe.PrepareConnect(socket, (*syscall.Sockaddr)(unsafe.Pointer(serverAddr)), uint64(serverAddrLen))
	sqe.UserData = eventTypeConnect
	ring.Submit()
}

func addReadRequest(socket int, ring *giouring.Ring, iovecs []syscall.Iovec, buffer *byte, blen uint64) {
	sqe := ring.GetSQE()
	iovecs[0] = syscall.Iovec{
		Base: buffer,
		Len:  blen,
	}
	sqe.PrepareReadv(socket, uintptr(unsafe.Pointer(&iovecs[0])), uint32(len(iovecs)), 0)
	sqe.UserData = eventTypeRead
	ring.Submit()
}

func addWriteRequest(socket int, ring *giouring.Ring, iovecs []syscall.Iovec, message *byte, mlen uint64) {
	sqe := ring.GetSQE()
	iovecs[0] = syscall.Iovec{
		Base: message,
		Len:  mlen,
	}
	sqe.PrepareWritev(socket, uintptr(unsafe.Pointer(&iovecs[0])), uint32(len(iovecs)), 0)
	sqe.UserData = eventTypeWrite
	ring.Submit()
}

func addRecvRequest(socket int, ring *giouring.Ring, msg *syscall.Msghdr) {
	sqe := ring.GetSQE()
	sqe.PrepareRecvMsg(socket, msg, 0)
	sqe.UserData = eventTypeRead
	ring.Submit()
}

func addSendRequest(socket int, ring *giouring.Ring, msg *syscall.Msghdr) {
	sqe := ring.GetSQE()
	sqe.PrepareSendMsg(socket, msg, 0)
	sqe.UserData = eventTypeWrite
	ring.Submit()
}

func addCloseRequest(socket int, ring *giouring.Ring, ty uint64) {
	sqe := ring.GetSQE()
	sqe.PrepareClose(socket)
	sqe.UserData = ty
	ring.Submit()
}

func runTcpIouServer() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("socket failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	addr := &unix.SockaddrInet4{
		Port: 8000,
		Addr: [4]byte{0, 0, 0, 0},
	}
	err = unix.Bind(fd, addr)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("bind failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}

	err = unix.Listen(fd, 1)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("listen failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}

	uring := giouring.NewRing()
	err = uring.QueueInit(64, 0)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("QueueInit failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}

	buffer := make([]byte, 1024)
	// The iovecs need to remain in scope until they have been processed on older kernels
	iovecs := make([]syscall.Iovec, 1)

	clientFd := 0

	fmt.Printf("Ready\n")

	// PrepareAccept is only available from v5.5
	if !kernels.MinKernelVersion("5.5.0") {
		clientFd, _, err = unix.Accept(fd)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Accept failed")
			panic(err)
		}
		addReadRequest(clientFd, uring, iovecs, &buffer[0], 1024)
	} else {
		clientAddr := unix.SockaddrInet4{}
		clientAddrLen := new(uint32)
		*clientAddrLen = unix.SizeofSockaddrAny
		addAcceptRequest(fd, uring, &clientAddr, clientAddrLen)
	}

	for {
		cqe, err := uring.WaitCQE()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("WaitCQE failed")
			panic(err)
		}
		uring.CQESeen(cqe)
		eventType := cqe.UserData
		if cqe.Res < 0 {
			panic(fmt.Errorf("async request failed: %d for event: %d", cqe.Res, eventType))
		}
		switch eventType {
		case eventTypeAccept:
			clientFd = int(cqe.Res)
			addReadRequest(clientFd, uring, iovecs, &buffer[0], 1024)
		case eventTypeRead:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty read received!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Read")
			addWriteRequest(clientFd, uring, iovecs, &buffer[0], uint64(cqe.Res))
		case eventTypeWrite:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty write sent!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Written")
			// PrepareClose is only available from v5.6
			if !kernels.MinKernelVersion("5.6.0") {
				err = unix.Close(clientFd)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("Close client failed")
					panic(err)
				}
				err = unix.Close(fd)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("Close server failed")
					panic(err)
				}
				os.Exit(0)
			} else {
				addCloseRequest(clientFd, uring, eventTypeCloseClient)
			}
		case eventTypeCloseClient:
			addCloseRequest(fd, uring, eventTypeClose)
		case eventTypeClose:
			os.Exit(0)
		}
	}
}

type my_sockaddr_in struct {
	sin_family uint16
	sin_port   uint16
	sin_addr   [4]byte
	sin_zero   [8]byte
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func runTcpIouClient() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		if sig == syscall.SIGTERM {
			os.Exit(0)
		}
	}()

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("socket failed")
		panic(err)
	}

	uring := giouring.NewRing()
	err = uring.QueueInit(64, 0)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("QueueInit failed")
		panic(err)
	}

	buffer := make([]byte, 1024)
	str := "hello"
	copy(buffer, str)
	// The iovecs need to remain in scope until they have been processed on older kernels
	iovecs := make([]syscall.Iovec, 1)

	// PrepareConnect is only available from v5.5
	if !kernels.MinKernelVersion("5.5.0") {
		serverAddr := unix.SockaddrInet4{
			Port: 8001,
			Addr: [4]byte{127, 0, 0, 1},
		}
		err = unix.Connect(fd, &serverAddr)
		if err != nil {
			logger.GetLogger().WithError(err).Warn("Connect failed")
			panic(err)
		}
		addWriteRequest(fd, uring, iovecs, &buffer[0], uint64(len(str)))
	} else {
		// PrepareConnect seems to want a sockaddr_in
		serverAddr := my_sockaddr_in{
			sin_family: unix.AF_INET,
			sin_port:   htons(8001),
			sin_addr:   [4]byte{127, 0, 0, 1},
		}
		addConnectRequest(fd, uring, &serverAddr, syscall.SizeofSockaddrInet4)
	}

	for {
		cqe, err := uring.WaitCQE()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("WaitCQE failed")
			panic(err)
		}
		uring.CQESeen(cqe)
		eventType := cqe.UserData
		if cqe.Res < 0 {
			panic(fmt.Errorf("async request failed: %d for event: %d", cqe.Res, eventType))
		}
		switch eventType {
		case eventTypeConnect:
			addWriteRequest(fd, uring, iovecs, &buffer[0], uint64(len(str)))
		case eventTypeWrite:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty write sent!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Written")
			// PrepareClose is only available from v5.6
			if !kernels.MinKernelVersion("5.6.0") {
				err = unix.Close(fd)
				if err != nil {
					logger.GetLogger().WithError(err).Warn("Close failed")
					panic(err)
				}
				os.Exit(0)
			} else {
				addCloseRequest(fd, uring, eventTypeClose)
			}
		case eventTypeClose:
			os.Exit(0)
		}
	}
}

func runUdpIouServer() {
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
		logger.GetLogger().WithError(err).Warn("socket failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}
	addr := &unix.SockaddrInet4{
		Port: 8000,
		Addr: [4]byte{0, 0, 0, 0},
	}
	err = unix.Bind(fd, addr)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("bind failed")
		fmt.Printf("NotReady: %s", err)
		panic(err)
	}

	uring := giouring.NewRing()
	err = uring.QueueInit(64, 0)
	if err != nil {
		logger.GetLogger().WithError(err).Warn("QueueInit failed")
		fmt.Printf("NotReady: %s", err)
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

	addRecvRequest(fd, uring, &msg)
	fmt.Printf("Ready\n")

	for {
		cqe, err := uring.WaitCQE()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("WaitCQE failed")
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
			addSendRequest(fd, uring, &msg)
		case eventTypeWrite:
			if cqe.Res == 0 {
				logger.GetLogger().Warn("Empty write sent!")
				continue
			}
			logger.GetLogger().WithFields(logrus.Fields{"buffer": buffer[:cqe.Res], "msg": string(buffer[:cqe.Res])}).Info("Written")
			addRecvRequest(fd, uring, &msg)
		}
	}
}
