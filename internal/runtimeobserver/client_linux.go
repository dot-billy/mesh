//go:build linux

package runtimeobserver

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type socketIdentity struct {
	device uint64
	inode  uint64
}

func observePlatform(ctx context.Context, validation ValidationContext, options clientOptions) (Snapshot, error) {
	if ctx == nil || validateContext(validation) != nil || validateClientOptions(options) != nil {
		return Snapshot{}, ErrTransport
	}
	request, err := NewRequest()
	if err != nil {
		return Snapshot{}, ErrTransport
	}
	requestLine, err := EncodeRequestLine(request)
	if err != nil {
		return Snapshot{}, ErrProtocol
	}

	totalContext, cancel := context.WithTimeout(ctx, options.totalTimeout)
	defer cancel()
	identity, err := validateSocket(options)
	if err != nil {
		return Snapshot{}, contextOrTransportError(totalContext)
	}
	dialer := net.Dialer{Timeout: options.dialTimeout}
	connection, err := dialer.DialContext(totalContext, "unix", options.socketPath)
	if err != nil {
		return Snapshot{}, contextOrTransportError(totalContext)
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(totalContext, func() { _ = connection.Close() })
	defer stopCancellation()

	connectedIdentity, err := validateSocket(options)
	if err != nil || connectedIdentity != identity || validatePeer(connection, options.expectedPeerUID) != nil {
		return Snapshot{}, ErrTransport
	}
	if err := connection.SetWriteDeadline(operationDeadline(totalContext, options.writeTimeout)); err != nil {
		return Snapshot{}, ErrTransport
	}
	if err := writeAll(connection, requestLine); err != nil {
		return Snapshot{}, contextOrTransportError(totalContext)
	}
	if err := connection.SetReadDeadline(operationDeadline(totalContext, options.readTimeout)); err != nil {
		return Snapshot{}, ErrTransport
	}
	response, err := io.ReadAll(io.LimitReader(connection, MaxResponseBytes+1))
	if err != nil {
		return Snapshot{}, contextOrTransportError(totalContext)
	}
	if len(response) > MaxResponseBytes {
		return Snapshot{}, ErrProtocol
	}
	snapshot, err := DecodeSnapshotLine(response, request.Nonce, validation)
	if err != nil {
		return Snapshot{}, ErrProtocol
	}
	return snapshot, nil
}

func validateClientOptions(options clientOptions) error {
	if !filepath.IsAbs(options.socketPath) || filepath.Clean(options.socketPath) != options.socketPath ||
		strings.ContainsRune(options.socketPath, '\x00') || options.socketPath == string(filepath.Separator) {
		return ErrTransport
	}
	if options.expectedMode != 0o600 || options.expectedParentMode != 0o700 ||
		options.dialTimeout <= 0 || options.writeTimeout <= 0 || options.readTimeout <= 0 || options.totalTimeout <= 0 {
		return ErrTransport
	}
	return nil
}

func validateSocket(options clientOptions) (socketIdentity, error) {
	volume := filepath.VolumeName(options.socketPath)
	remainder := strings.TrimPrefix(options.socketPath, volume+string(filepath.Separator))
	current := volume + string(filepath.Separator)
	components := strings.Split(remainder, string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." || component == ".." {
			return socketIdentity{}, ErrTransport
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return socketIdentity{}, ErrTransport
		}
		if index < len(components)-1 && !info.IsDir() {
			return socketIdentity{}, ErrTransport
		}
	}

	parentInfo, err := os.Lstat(filepath.Dir(options.socketPath))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != os.FileMode(options.expectedParentMode) {
		return socketIdentity{}, ErrTransport
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != options.expectedUID {
		return socketIdentity{}, ErrTransport
	}

	socketInfo, err := os.Lstat(options.socketPath)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 || socketInfo.Mode().Perm() != os.FileMode(options.expectedMode) {
		return socketIdentity{}, ErrTransport
	}
	socketStat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || socketStat.Uid != options.expectedUID || socketStat.Nlink != 1 {
		return socketIdentity{}, ErrTransport
	}
	return socketIdentity{device: uint64(socketStat.Dev), inode: socketStat.Ino}, nil
}

func validatePeer(connection net.Conn, expectedUID uint32) error {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return ErrTransport
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return ErrTransport
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fileDescriptor uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fileDescriptor), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || controlErr != nil || credential == nil || credential.Uid != expectedUID {
		return ErrTransport
	}
	return nil
}

func writeAll(destination io.Writer, message []byte) error {
	for len(message) != 0 {
		written, err := destination.Write(message)
		if err != nil {
			return ErrTransport
		}
		if written <= 0 || written > len(message) {
			return ErrTransport
		}
		message = message[written:]
	}
	return nil
}

func operationDeadline(ctx context.Context, limit time.Duration) time.Time {
	deadline := time.Now().Add(limit)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func contextOrTransportError(ctx context.Context) error {
	if err := ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return ErrTransport
}
