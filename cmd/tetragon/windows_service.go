//go:build windows

package tetragon

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

type tetragonService struct{}

const (
	Pending   int = 1
	Running   int = 2
	Completed int = 3
)

var status chan int

// This function updates the status channel to pending status,
// which signifies the main tetragon thread is initializing...
// This status is consumed by the main service thread to post
// service status into the svc.Status channel. Everytime we update
// the channel, the progress bar on Windows service console moves
// forward, indicating the service's one more step toward fully starting
func updateServiceStarting() {
	if status != nil {
		status <- Pending
	}
}

func (m *tetragonService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {

	ctx, cancel := context.WithCancel(context.Background())
	status = make(chan int)
	updateSrvStarted := func() {
		status <- Running
	}

	changes <- svc.Status{State: svc.StartPending}

	go func() {
		tetragonExecuteCtx(ctx, cancel, updateSrvStarted)
		// return means tetragon did not start
		status <- Completed
	}()

statusLoop:
	for srvStatus := range status {
		switch srvStatus {
		case Pending:
			time.Sleep(100 * time.Millisecond)
			changes <- svc.Status{State: svc.StartPending}
			continue
		case Completed:
			log.Error("unexpected return from init routine. service not started")
			return
		case Running:
			break statusLoop
		}
	}
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				cancel()
				continue
			default:
				log.Error("unexpected control request", "Request Code", c)
			}
		case srvStatus := <-status:
			switch srvStatus {
			case Completed:
				break loop
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return false, uint32(windows.APPLICATION_ERROR)
}

func runAsWindowsService() error {
	err := svc.Run("TetragonEnterprise", &tetragonService{})
	if err != nil {
		return fmt.Errorf("running as service failed  %v", err)
	}
	return err
}
