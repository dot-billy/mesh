// mesh-origin serves an explicit, digest-verified public release allowlist.
// It holds no release trust or signing key; installers authenticate all bytes.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mesh/internal/releaseorigin"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == kubernetesTLSMaterializeCommand {
		if err := runKubernetesTLSMaterializer(os.Args[2:]); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "mesh-origin Kubernetes TLS materializer:", err)
			os.Exit(1)
		}
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	config, err := parseOriginConfig(os.Args[1:])
	if err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}
	certificate, err := loadOriginCertificate(config.tlsCert, config.tlsKey)
	if err != nil {
		logger.Error("TLS configuration error", "error", err)
		os.Exit(1)
	}
	store, err := releaseorigin.OpenFiles(config.root, config.index)
	if err != nil {
		logger.Error("release origin startup failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	server := &http.Server{
		Addr:              config.listen,
		Handler:           store.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		},
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	logger.Info("release origin started", "listen", config.listen, "public_url", config.publicURL)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("release origin stopped", "error", err)
		os.Exit(1)
	}
}
