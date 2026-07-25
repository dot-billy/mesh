//go:build !linux

package runtimeobserver

import "context"

func observePlatform(context.Context, ValidationContext, clientOptions) (Snapshot, error) {
	return Snapshot{}, ErrUnavailable
}
