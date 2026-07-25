package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"mesh/internal/onlinerelease"
)

type originConfig struct {
	listen    string
	publicURL string
	tlsCert   string
	tlsKey    string
	root      string
	index     string
}

func parseOriginConfig(arguments []string) (originConfig, error) {
	var config originConfig
	flags := flag.NewFlagSet("mesh-origin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&config.listen, "listen", "", "explicit IP and fixed port for the HTTPS listener")
	flags.StringVar(&config.publicURL, "public-url", "", "canonical public HTTPS origin")
	flags.StringVar(&config.tlsCert, "tls-cert", "", "clean absolute TLS certificate path")
	flags.StringVar(&config.tlsKey, "tls-key", "", "clean absolute private TLS key path")
	flags.StringVar(&config.root, "root", "", "clean absolute read-only public object root")
	flags.StringVar(&config.index, "index", "", "clean absolute canonical release-origin index")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return originConfig{}, errors.New("invalid release-origin configuration")
	}
	host, portText, err := net.SplitHostPort(config.listen)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || net.ParseIP(host) == nil || strings.Contains(host, "%") || port < 1 || port > 65535 {
		return originConfig{}, errors.New("--listen must use an explicit IP address and fixed port")
	}
	if config.publicURL == "" {
		return originConfig{}, errors.New("--public-url is required")
	}
	parsedPublicURL, err := url.Parse(config.publicURL)
	if err != nil || parsedPublicURL.Scheme != "https" || parsedPublicURL.Host == "" || parsedPublicURL.User != nil ||
		parsedPublicURL.Path != "" || parsedPublicURL.RawPath != "" || parsedPublicURL.RawQuery != "" || parsedPublicURL.Fragment != "" {
		return originConfig{}, errors.New("--public-url must be one canonical HTTPS origin without a path, query, fragment, credentials, or default port")
	}
	probeURL := config.publicURL + "/channels/stable/bundle.json"
	canonical, err := onlinerelease.CanonicalBundleURL(probeURL)
	if err != nil || canonical != probeURL {
		return originConfig{}, errors.New("--public-url must be one canonical HTTPS origin without a path, query, fragment, credentials, or default port")
	}
	for name, path := range map[string]string{
		"--tls-cert": config.tlsCert,
		"--tls-key":  config.tlsKey,
		"--root":     config.root,
		"--index":    config.index,
	} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == string(filepath.Separator) {
			return originConfig{}, errors.New(name + " must be a clean absolute non-root path")
		}
	}
	return config, nil
}
