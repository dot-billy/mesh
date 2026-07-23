package main

import (
	"fmt"
	"strings"
	"unicode"

	"mesh/internal/buildinfo"
)

const maxReportedAgentVersion = 160

func currentMeshAgentVersion() (string, error) {
	info, err := buildinfo.Current()
	if err != nil {
		return "", fmt.Errorf("load Mesh build identity: %w", err)
	}
	version := strings.TrimSpace(info.Version)
	if version == "" || version != info.Version || len(version) > 128 {
		return "", fmt.Errorf("invalid Mesh build version %q", info.Version)
	}
	for _, character := range version {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return "", fmt.Errorf("invalid Mesh build version %q", info.Version)
		}
	}
	reported := "meshctl/" + version
	if len(reported) > maxReportedAgentVersion {
		return "", fmt.Errorf("reported Mesh agent version exceeds %d bytes", maxReportedAgentVersion)
	}
	return reported, nil
}
