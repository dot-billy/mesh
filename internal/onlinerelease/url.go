package onlinerelease

import (
	"errors"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
)

// CanonicalBundleURL validates by rejection rather than normalization so the
// operator, browser, and privileged installer all retain one exact locator.
func CanonicalBundleURL(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("bundle URL must not be empty or have surrounding whitespace")
	}
	for _, character := range raw {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", errors.New("bundle URL must not contain whitespace or control characters")
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Scheme != "https" || parsed.Opaque != "" ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.RawPath != "" {
		return "", errors.New("bundle URL must be one absolute HTTPS URL without user information, query, or fragment")
	}
	if parsed.Path == "" || parsed.Path == "/" || !strings.HasPrefix(parsed.Path, "/") ||
		path.Clean(parsed.Path) != parsed.Path || strings.Contains(parsed.Path, "//") {
		return "", errors.New("bundle URL path must name one canonical absolute object")
	}
	if strings.Contains(parsed.Hostname(), "%") || strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("bundle URL host or port is not canonical")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 || value == 443 {
			return "", errors.New("bundle URL explicit port must be a nondefault decimal number from 1 through 65535")
		}
	}
	if strings.ToLower(parsed.Host) != parsed.Host || parsed.String() != raw {
		return "", errors.New("bundle URL authority or encoding is not canonical")
	}
	return raw, nil
}
