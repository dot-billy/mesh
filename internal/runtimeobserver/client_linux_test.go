//go:build linux

package runtimeobserver

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestObservePlatformUsesOneCanonicalUnixRequest(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	path, done := startResponseServer(t, func(request Request) ([]byte, error) {
		snapshot := validSnapshot()
		snapshot.Nonce = request.Nonce
		return EncodeSnapshotLine(snapshot, request.Nonce, validation)
	})
	options := testClientOptions(path)
	snapshot, err := observePlatform(context.Background(), validation, options)
	if err != nil {
		t.Fatalf("observePlatform: %v", err)
	}
	if !validNonce(snapshot.Nonce) || snapshot.SampleSequence != 42 || snapshot.ProcessInstanceID != "fedcba9876543210fedcba9876543210" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	waitForServer(t, done)
}

func TestObservePlatformRejectsAdversarialResponses(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	tests := map[string]struct {
		response func(Request) ([]byte, error)
		wantErr  error
	}{
		"malformed": {
			response: func(Request) ([]byte, error) { return []byte("not-json\n"), nil },
			wantErr:  ErrProtocol,
		},
		"duplicate": {
			response: func(request Request) ([]byte, error) {
				line := responseForRequest(t, request, validation)
				needle := `"nonce":"` + request.Nonce + `"`
				return []byte(strings.Replace(string(line), needle, needle+`,`+needle, 1)), nil
			},
			wantErr: ErrProtocol,
		},
		"unknown": {
			response: func(request Request) ([]byte, error) {
				line := responseForRequest(t, request, validation)
				return []byte(strings.Replace(string(line), `{"schema":`, `{"private_key":"forbidden","schema":`, 1)), nil
			},
			wantErr: ErrProtocol,
		},
		"nonce mismatch": {
			response: func(request Request) ([]byte, error) {
				snapshot := validSnapshot()
				snapshot.Nonce = testNonce
				return rawSnapshot(snapshot), nil
			},
			wantErr: ErrProtocol,
		},
		"oversized": {
			response: func(Request) ([]byte, error) { return bytes.Repeat([]byte{'x'}, MaxResponseBytes+1), nil },
			wantErr:  ErrProtocol,
		},
		"trailing after line": {
			response: func(request Request) ([]byte, error) {
				return append(responseForRequest(t, request, validation), []byte("forbidden")...), nil
			},
			wantErr: ErrProtocol,
		},
	}
	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, done := startResponseServer(t, test.response)
			_, err := observePlatform(context.Background(), validation, testClientOptions(path))
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("observePlatform error = %v, want %v", err, test.wantErr)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "forbidden") || strings.Contains(err.Error(), testNonce) {
				t.Fatalf("error leaked untrusted data: %q", err)
			}
			waitForServer(t, done)
		})
	}
}

func TestObservePlatformBoundsSlowResponseAndClose(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	tests := map[string]func(net.Conn) error{
		"slow response": func(connection net.Conn) error {
			if _, err := readRequest(connection); err != nil {
				return err
			}
			time.Sleep(150 * time.Millisecond)
			return nil
		},
		"slow close": func(connection net.Conn) error {
			request, err := readRequest(connection)
			if err != nil {
				return err
			}
			if _, err := connection.Write(responseForRequest(t, request, validation)); err != nil {
				return err
			}
			time.Sleep(150 * time.Millisecond)
			return nil
		},
	}
	for name, handler := range tests {
		handler := handler
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			path, done := startSocketServer(t, handler)
			options := testClientOptions(path)
			options.readTimeout = 30 * time.Millisecond
			options.totalTimeout = 100 * time.Millisecond
			started := time.Now()
			_, err := observePlatform(context.Background(), validation, options)
			if !errors.Is(err, ErrTransport) {
				t.Fatalf("observePlatform error = %v, want ErrTransport", err)
			}
			if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
				t.Fatalf("bounded read took %s", elapsed)
			}
			waitForServer(t, done)
		})
	}
}

func TestObservePlatformHonorsCancellationAndTotalDeadline(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")
	path, done := startSocketServer(t, func(connection net.Conn) error {
		if _, err := readRequest(connection); err != nil {
			return err
		}
		time.Sleep(150 * time.Millisecond)
		return nil
	})
	options := testClientOptions(path)
	options.readTimeout = 100 * time.Millisecond
	options.totalTimeout = 40 * time.Millisecond
	_, err := observePlatform(context.Background(), validation, options)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("total deadline error = %v, want context.DeadlineExceeded", err)
	}
	waitForServer(t, done)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	options.socketPath = filepath.Join(t.TempDir(), "missing.sock")
	_, err = observePlatform(canceled, validation, options)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v, want context.Canceled", err)
	}
}

func TestObservePlatformRejectsUnsafeSocketPaths(t *testing.T) {
	t.Parallel()
	validation := testValidation(t, "10.42.0.1", "10.42.0.2")

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "observer.sock")
		if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
			t.Fatal(err)
		}
		assertTransportFailure(t, path, validation, nil)
	})

	t.Run("wrong socket mode", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		if err := os.Chmod(path, 0o660); err != nil {
			t.Fatal(err)
		}
		assertTransportFailure(t, path, validation, nil)
	})

	t.Run("wrong parent mode", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		assertTransportFailure(t, path, validation, nil)
	})

	t.Run("symlinked parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		realPath := filepath.Join(realParent, "observer.sock")
		listener, err := net.Listen("unix", realPath)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if err := os.Chmod(realPath, 0o600); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(root, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		assertTransportFailure(t, filepath.Join(linkedParent, "observer.sock"), validation, nil)
	})

	t.Run("symlinked socket", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		link := filepath.Join(filepath.Dir(path), "linked.sock")
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		assertTransportFailure(t, link, validation, nil)
	})

	t.Run("hard-linked socket", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		link := filepath.Join(filepath.Dir(path), "linked.sock")
		if err := os.Link(path, link); err != nil {
			t.Skipf("filesystem does not support hard-linking Unix sockets: %v", err)
		}
		assertTransportFailure(t, path, validation, nil)
	})

	t.Run("relative path", func(t *testing.T) {
		assertTransportFailure(t, "observer.sock", validation, nil)
	})

	t.Run("unclean path", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "child", "..", "observer.sock")
		assertTransportFailure(t, path, validation, nil)
	})

	t.Run("wrong peer uid", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		options := testClientOptions(path)
		options.expectedPeerUID++
		assertTransportFailure(t, path, validation, &options)
	})

	t.Run("unvalidated topology", func(t *testing.T) {
		path, listener := newTestSocket(t)
		defer listener.Close()
		assertTransportFailure(t, path, ValidationContext{}, nil)
	})
}

func TestProductionClientOptionsAreFixedAndBounded(t *testing.T) {
	t.Parallel()
	options := productionClientOptions()
	if options.socketPath != DefaultSocketPath || options.expectedUID != 0 || options.expectedPeerUID != 0 ||
		options.expectedMode != 0o600 || options.expectedParentMode != 0o700 {
		t.Fatalf("unsafe production socket options: %#v", options)
	}
	if options.dialTimeout != 500*time.Millisecond || options.writeTimeout != 250*time.Millisecond ||
		options.readTimeout != time.Second || options.totalTimeout != 2*time.Second {
		t.Fatalf("unexpected production deadlines: %#v", options)
	}
	if err := validateClientOptions(options); err != nil {
		t.Fatalf("production options rejected: %v", err)
	}
}

func startResponseServer(t *testing.T, response func(Request) ([]byte, error)) (string, <-chan error) {
	t.Helper()
	return startSocketServer(t, func(connection net.Conn) error {
		request, err := readRequest(connection)
		if err != nil {
			return err
		}
		message, err := response(request)
		if err != nil {
			return err
		}
		_, err = connection.Write(message)
		return err
	})
}

func startSocketServer(t *testing.T, handler func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	path, listener := newTestSocket(t)
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		done <- handler(connection)
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return path, done
}

func newTestSocket(t *testing.T) (string, net.Listener) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "runtime-observer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path, listener
}

func readRequest(connection net.Conn) (Request, error) {
	reader := bufio.NewReaderSize(connection, MaxRequestBytes+1)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return Request{}, err
	}
	if reader.Buffered() != 0 {
		return Request{}, ErrProtocol
	}
	return DecodeRequestLine(line)
}

func responseForRequest(t *testing.T, request Request, validation ValidationContext) []byte {
	t.Helper()
	snapshot := validSnapshot()
	snapshot.Nonce = request.Nonce
	line, err := EncodeSnapshotLine(snapshot, request.Nonce, validation)
	if err != nil {
		t.Fatalf("EncodeSnapshotLine: %v", err)
	}
	return line
}

func waitForServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("test observer: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("test observer did not stop")
	}
}

func testClientOptions(path string) clientOptions {
	options := productionClientOptions()
	options.socketPath = path
	options.expectedUID = uint32(os.Geteuid())
	options.expectedPeerUID = uint32(os.Geteuid())
	options.dialTimeout = 100 * time.Millisecond
	options.writeTimeout = 100 * time.Millisecond
	options.readTimeout = 200 * time.Millisecond
	options.totalTimeout = 300 * time.Millisecond
	return options
}

func assertTransportFailure(t *testing.T, path string, validation ValidationContext, provided *clientOptions) {
	t.Helper()
	options := testClientOptions(path)
	if provided != nil {
		options = *provided
	}
	_, err := observePlatform(context.Background(), validation, options)
	if !errors.Is(err, ErrTransport) {
		t.Fatalf("observePlatform error = %v, want ErrTransport", err)
	}
	if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), testNonce) {
		t.Fatalf("transport error leaked path or nonce: %q", err)
	}
}
