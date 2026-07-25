package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"mesh/internal/darwinnativeevidence"
)

func verifyDarwinNativeEvidence(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-darwin-native-evidence", flag.ContinueOnError)
	evidenceDirectory := flags.String("evidence-dir", "", "create-only Darwin native v3 evidence directory")
	arch := flags.String("arch", "", "expected Darwin architecture (amd64 or arm64)")
	bundleSHA256 := flags.String("bundle-sha256", "", "expected Darwin bundle SHA-256")
	nowValue := flags.String("now", "", "optional canonical whole-second UTC verification time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-darwin-native-evidence does not accept positional arguments")
	}
	for _, value := range []struct{ name, value string }{
		{"--evidence-dir", *evidenceDirectory}, {"--arch", *arch}, {"--bundle-sha256", *bundleSHA256},
	} {
		if strings.TrimSpace(value.value) == "" {
			return fmt.Errorf("%s is required", value.name)
		}
	}
	now := time.Now().UTC()
	if strings.TrimSpace(*nowValue) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*nowValue))
		if err != nil || parsed.UTC().Format(time.RFC3339) != strings.TrimSpace(*nowValue) {
			return errors.New("--now must be canonical whole-second UTC RFC3339")
		}
		now = parsed
	}
	evidence, err := darwinnativeevidence.InspectDirectory(strings.TrimSpace(*evidenceDirectory))
	if err != nil {
		return err
	}
	if err := evidence.MatchFull(now, strings.TrimSpace(*arch), strings.TrimSpace(*bundleSHA256)); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Verified fresh canonical full-system Darwin native evidence for darwin/%s and bundle %s, including system launchctl mutation. This is local clean-host evidence, not codesigning, notarization, or remote attestation.\n", strings.TrimSpace(*arch), strings.TrimSpace(*bundleSHA256))
	return err
}
