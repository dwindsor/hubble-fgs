//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package heartbeat

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/timer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const (
	heartbeatIntervalDefault = time.Duration(60 * time.Second)
	heartbeatUDPPortDefault  = 6399
	heartbeatTCPPortDefault  = 6399
	versionStr               = "__heartbeat__"
)

var (
	heartbeatTimer = timer.NewPeriodicTimer("Heartbeat", heartbeat, true)
	mutex          sync.Mutex
	running        = false
	connectUDP     net.Conn
	connectTCP     net.Conn
	closeUDP       chan struct{}
	errChan        chan error
	runningUDP     = false
	runningTCP     = false
)

func listenerTcp(addr string) {
	logger.GetLogger().Infof("Heartbeat starting TCP listener: '%s'", addr)
	listen, err := net.Listen("tcp4", addr)
	if err != nil {
		errChan <- err
		logger.GetLogger().WithError(err).Warnf("Heartbeat TCP listener failed to listen for '%s'", addr)
		return
	}
	errChan <- nil
	defer listen.Close()

	logger.GetLogger().Infof("Heartbeat TCP listening: '%s'", addr)
	accept, err := listen.Accept()
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Heartbeat TCP accept failed for '%s'", addr)
		return
	}
	defer accept.Close()

	buffer := make([]byte, 1)

	for {
		n, err := accept.Read(buffer)
		if n == 0 || err != nil {
			// socket was closed or error occurred
			logger.GetLogger().Info("Heartbeat stopping TCP listener")
			return
		}
	}
}

func listenerUdp(addr string) {
	logger.GetLogger().Infof("Heartbeat starting UDP listener: '%s'", addr)
	listen, err := net.ListenPacket("udp4", addr)
	if err != nil {
		errChan <- err
		logger.GetLogger().WithError(err).Warnf("Heartbeat UDP listener failed to listen for '%s'", addr)
		return
	}
	errChan <- nil
	defer listen.Close()

	logger.GetLogger().Infof("Heartbeat UDP listening: '%s'", addr)

	buffer := make([]byte, 1)

	for {
		select {
		case <-closeUDP:
			logger.GetLogger().Info("Heartbeat stopping UDP listener")
			return
		default:
			listen.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			listen.ReadFrom(buffer)
		}
	}
}

func connect(proto string, dest string) (net.Conn, error) {
	conn, err := net.Dial(proto, dest)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to connect to %s listener", strings.ToUpper(proto)[0:3])
		return nil, err
	}
	return conn, nil
}

func start(interval time.Duration, udpPort uint32, tcpPort uint32) error {
	// create UDP stopping channel
	closeUDP = make(chan struct{})
	// create error channel
	errChan = make(chan error)

	// create listeners
	go listenerUdp(fmt.Sprintf("127.0.0.1:%d", udpPort))
	err := <-errChan
	if err == nil {
		runningUDP = true
	}
	go listenerTcp(fmt.Sprintf("127.0.0.1:%d", tcpPort))
	err = <-errChan
	if err == nil {
		runningTCP = true
	}

	// connect to listeners
	if runningUDP {
		connectUDP, err = connect("udp4", fmt.Sprintf("localhost:%d", udpPort))
		if err != nil {
			close(closeUDP)
			runningUDP = false
		}
	}

	if runningTCP {
		connectTCP, err = connect("tcp4", fmt.Sprintf("localhost:%d", tcpPort))
		if err != nil {
			runningTCP = false
		}
	}

	if runningUDP || runningTCP {
		logger.GetLogger().Info("Heartbeat Starting timer")
		heartbeatTimer.Start(interval)
		return nil
	}

	return fmt.Errorf("heartbeat: neither UDP or TCP connections could be started")
}

func unloadHeartbeatSensor() error {
	mutex.Lock()
	defer mutex.Unlock()
	if !running {
		logger.GetLogger().Error("Heartbeat is not running")
		return nil
	}
	heartbeatTimer.Stop()
	if runningUDP {
		close(closeUDP)
		connectUDP.Close()
		runningUDP = false
	}
	if runningTCP {
		connectTCP.Close()
		runningTCP = false
	}
	running = false
	return nil
}

func heartbeat() {
	buffer := make([]byte, 1)
	buffer[0] = 'A'
	if runningUDP {
		connectUDP.Write(buffer)
	}
	if runningTCP {
		connectTCP.Write(buffer)
	}
}

type heartbeatSensor struct {
	name string
}

func (hb *heartbeatSensor) PolicyHandler(
	policy tracingpolicy.TracingPolicy,
	fid policyfilter.PolicyID,
) (*sensors.Sensor, error) {
	mutex.Lock()
	defer mutex.Unlock()

	// Attempting to reconfigure an already running heartbeat is an error.
	if running {
		logger.GetLogger().Error("Heartbeat is already running")
		return nil, fmt.Errorf("heartbeat is already running")
	}

	spec := policy.TpSpec()
	interval := heartbeatIntervalDefault
	tcpPort := uint32(heartbeatTCPPortDefault)
	udpPort := uint32(heartbeatUDPPortDefault)

	if !spec.Parser.Heartbeat.Enable {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("heartbeat sensor does not implement policy filtering")
	}

	if spec.Parser.Heartbeat.Interval > 0 {
		interval = time.Duration(spec.Parser.Heartbeat.Interval) * time.Second
	}
	if spec.Parser.Heartbeat.TcpPort > 0 {
		tcpPort = spec.Parser.Heartbeat.TcpPort
	}
	if spec.Parser.Heartbeat.UdpPort > 0 {
		udpPort = spec.Parser.Heartbeat.UdpPort
	}

	hbSensor := sensors.SensorBuilder(versionStr, nil, nil)
	hbSensor.PreUnloadHook = unloadHeartbeatSensor

	start(interval, udpPort, tcpPort)
	running = true
	heartbeat()

	return hbSensor, nil
}

func (hb *heartbeatSensor) LoadProbe(_ sensors.LoadProbeArgs) error {
	return nil
}

func init() {
	AddHeartbeat()
}

func AddHeartbeat() {
	hb := &heartbeatSensor{
		name: "Heartbeat",
	}
	sensors.RegisterProbeType("heartbeat", hb)
	sensors.RegisterPolicyHandlerAtInit(hb.name, hb)
}
