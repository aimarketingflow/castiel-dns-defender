//go:build windows

package main

import (
	"context"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

// castielService implements svc.Handler for running as a Windows Service.
type castielService struct {
	runDaemon func(context.Context)
}

func (s *castielService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Start Castiel daemon in goroutine
	ctx, cancel := context.WithCancel(context.Background())
	go s.runDaemon(ctx)

	// Give daemon time to start
	time.Sleep(2 * time.Second)

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown}

	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			log.Printf("Windows Service: received stop/shutdown")
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			time.Sleep(2 * time.Second) // Grace period
			changes <- svc.Status{State: svc.Stopped}
			return
		case svc.PreShutdown:
			log.Printf("Windows Service: received preshutdown")
			changes <- svc.Status{State: svc.StopPending}
			cancel()
			time.Sleep(2 * time.Second)
			changes <- svc.Status{State: svc.Stopped}
			return
		}
	}
}

// isWindowsService reports whether the process is running as a Windows Service.
func isWindowsService() bool {
	is, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return is
}

// runAsService runs Castiel as a Windows Service via SCM.
func runAsService(runDaemon func(context.Context)) error {
	return svc.Run("Castiel", &castielService{runDaemon: runDaemon})
}
