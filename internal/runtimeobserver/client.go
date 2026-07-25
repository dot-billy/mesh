package runtimeobserver

import (
	"context"
	"errors"
	"time"
)

const (
	DefaultSocketPath   = "/run/mesh-nebula/runtime-observer.sock"
	DefaultDialTimeout  = 500 * time.Millisecond
	DefaultWriteTimeout = 250 * time.Millisecond
	DefaultReadTimeout  = time.Second
	DefaultTotalTimeout = 2 * time.Second
)

var (
	ErrUnavailable = errors.New("runtime observer unavailable")
	ErrTransport   = errors.New("runtime observer transport failure")
)

// Client has no configurable production endpoint. The zero value is ready for
// use and always targets DefaultSocketPath with fixed bounded deadlines.
type Client struct{}

// Observe requests one snapshot over one connection. It never retries or
// falls back to HTTP, TCP, another socket, or a cached sample.
func (Client) Observe(ctx context.Context, validation ValidationContext) (Snapshot, error) {
	return observePlatform(ctx, validation, productionClientOptions())
}

type clientOptions struct {
	socketPath         string
	expectedUID        uint32
	expectedPeerUID    uint32
	expectedMode       uint32
	expectedParentMode uint32
	dialTimeout        time.Duration
	writeTimeout       time.Duration
	readTimeout        time.Duration
	totalTimeout       time.Duration
}

func productionClientOptions() clientOptions {
	return clientOptions{
		socketPath:         DefaultSocketPath,
		expectedUID:        0,
		expectedPeerUID:    0,
		expectedMode:       0o600,
		expectedParentMode: 0o700,
		dialTimeout:        DefaultDialTimeout,
		writeTimeout:       DefaultWriteTimeout,
		readTimeout:        DefaultReadTimeout,
		totalTimeout:       DefaultTotalTimeout,
	}
}
