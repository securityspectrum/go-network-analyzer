//go:build windows
// +build windows

package main

import (
	"log"

	"golang.org/x/sys/windows/svc"
)

func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Printf("Failed to determine if we are running in a Windows Service: %v", err)
		return false
	}
	return isService
}

func runService(name string) {
	err := svc.Run(name, &myService{})
	if err != nil {
		log.Fatalf("Failed to run service: %v", err)
	}
}

type myService struct{}

func (m *myService) Execute(args []string, req <-chan svc.ChangeRequest, statusChan chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	statusChan <- svc.Status{State: svc.StartPending}

	// Start your service
	stopChan := make(chan struct{})
	go func() {
		runApplication(stopChan)
	}()
	statusChan <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

loop:
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				statusChan <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// Stop the service
				statusChan <- svc.Status{State: svc.StopPending}
				close(stopChan)
				break loop
			default:
				log.Printf("Unexpected control request #%d", c)
			}
		}
	}
	statusChan <- svc.Status{State: svc.Stopped}
	return false, 0
}
