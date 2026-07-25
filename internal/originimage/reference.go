// Package originimage verifies the independently provisioned signature on one
// exact release-origin container image. Image authentication is a deployment
// control; it does not grant release-signing authority.
package originimage

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var (
	registryLabelPattern = `[a-z0-9](?:[a-z0-9-]*[a-z0-9])?`
	registryPattern      = `(?:localhost|` + registryLabelPattern + `(?:\.` + registryLabelPattern + `)+)(?::[1-9][0-9]{0,4})?`
	repositoryPart       = `[a-z0-9]+(?:[._-][a-z0-9]+)*`
	referencePattern     = regexp.MustCompile(`^(` + registryPattern + `/` + repositoryPart + `(?:/` + repositoryPart + `)*)@sha256:([0-9a-f]{64})$`)
)

type Reference struct {
	Canonical  string
	Repository string
	Digest     string
}

func ParseReference(value string) (Reference, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t ") {
		return Reference{}, errors.New("origin image must be one canonical registry repository and SHA-256 digest")
	}
	matches := referencePattern.FindStringSubmatch(value)
	if len(matches) != 3 {
		return Reference{}, errors.New("origin image must have canonical registry/repository@sha256:<64 lowercase hexadecimal> form")
	}
	registry := strings.SplitN(matches[1], "/", 2)[0]
	if separator := strings.LastIndexByte(registry, ':'); separator >= 0 {
		port, err := strconv.Atoi(registry[separator+1:])
		if err != nil || port < 1 || port > 65535 {
			return Reference{}, errors.New("origin image registry port must be between 1 and 65535")
		}
	}
	return Reference{Canonical: value, Repository: matches[1], Digest: matches[2]}, nil
}
