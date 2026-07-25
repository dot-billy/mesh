//go:build windows

package main

import (
	"context"
	"errors"
	"os/signal"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

const windowsAgentServiceName = "MeshNodeAgent"

func runAgent(args []string) error {
	service, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !service {
		ctx, stop := signal.NotifyContext(context.Background(), agentSignals()...)
		defer stop()
		return runAgentWithContext(ctx, args)
	}
	handler := &windowsAgentServiceHandler{args: append([]string(nil), args...)}
	if err := svc.Run(windowsAgentServiceName, handler); err != nil {
		return err
	}
	return handler.result()
}

type windowsAgentServiceHandler struct {
	args []string

	mu  sync.Mutex
	err error
}

func (handler *windowsAgentServiceHandler) Execute(startArgs []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending, WaitHint: 30_000}
	if len(startArgs) != 1 || startArgs[0] != windowsAgentServiceName {
		handler.setResult(errors.New("Windows agent service start parameters are not canonical"))
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	ready := make(chan struct{})
	go func() { done <- runAgentWithReady(ctx, handler.args, func() { close(ready) }) }()
	select {
	case err := <-done:
		handler.setResult(err)
		if err != nil {
			return true, 1
		}
		return false, 0
	case <-ready:
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			handler.setResult(err)
			if err != nil {
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 120_000}
				cancel()
				select {
				case err := <-done:
					handler.setResult(err)
					if err != nil {
						return true, 1
					}
					return false, 0
				case <-time.After(2 * time.Minute):
					handler.setResult(errors.New("Windows agent service did not stop within its lifecycle bound"))
					return true, 1
				}
			}
		}
	}
}

func (handler *windowsAgentServiceHandler) setResult(err error) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	handler.err = err
}

func (handler *windowsAgentServiceHandler) result() error {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.err
}
