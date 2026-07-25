//go:build !windows

package main

import (
	"context"
	"os/signal"
)

func runAgent(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), agentSignals()...)
	defer stop()
	return runAgentWithContext(ctx, args)
}
