package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"mesh/internal/windowsnativeevidence"
)

func verifyWindowsNativeEvidence(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-windows-native-evidence", flag.ContinueOnError)
	bootstrapPath := flags.String("bootstrap-receipt", "", "canonical clean-host Windows bootstrap receipt")
	runtimePath := flags.String("runtime-receipt", "", "canonical clean-host Windows runtime v4 receipt")
	arch := flags.String("arch", "", "expected Windows architecture (amd64 or arm64)")
	policySHA256 := flags.String("authenticode-policy-sha256", "", "expected compiled Authenticode policy SHA-256")
	installerSHA256 := flags.String("installer-sha256", "", "expected signed installer SHA-256")
	bundleSHA256 := flags.String("bundle-sha256", "", "expected initial signed-v3 bundle SHA-256")
	upgradeBundleSHA256 := flags.String("upgrade-bundle-sha256", "", "expected upgrade signed-v3 bundle SHA-256")
	nowValue := flags.String("now", "", "optional canonical whole-second UTC verification time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify-windows-native-evidence does not accept positional arguments")
	}
	values := []struct{ name, value string }{
		{"--bootstrap-receipt", *bootstrapPath}, {"--runtime-receipt", *runtimePath}, {"--arch", *arch},
		{"--authenticode-policy-sha256", *policySHA256}, {"--installer-sha256", *installerSHA256},
		{"--bundle-sha256", *bundleSHA256}, {"--upgrade-bundle-sha256", *upgradeBundleSHA256},
	}
	for _, value := range values {
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
	bootstrapRaw, err := readAuthoringPublicFile("Windows native bootstrap receipt", strings.TrimSpace(*bootstrapPath), windowsnativeevidence.MaximumBootstrapSize)
	if err != nil {
		return err
	}
	bootstrap, err := windowsnativeevidence.ParseBootstrapReceipt(bootstrapRaw)
	if err != nil {
		return err
	}
	runtimeRaw, err := readAuthoringPublicFile("Windows native runtime receipt", strings.TrimSpace(*runtimePath), windowsnativeevidence.MaximumRuntimeSize)
	if err != nil {
		return err
	}
	runtime, err := windowsnativeevidence.ParseRuntimeReceipt(runtimeRaw)
	if err != nil {
		return err
	}
	if err := windowsnativeevidence.MatchPair(
		now, bootstrap, runtime, strings.TrimSpace(*arch), strings.TrimSpace(*policySHA256),
		strings.TrimSpace(*installerSHA256), strings.TrimSpace(*bundleSHA256), strings.TrimSpace(*upgradeBundleSHA256),
	); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "Verified fresh canonical Windows native evidence for windows/%s: bootstrap installer %s, initial bundle %s, upgrade bundle %s, and Authenticode policy %s. The receipts are local clean-host evidence, not remote attestation.\n",
		strings.TrimSpace(*arch), strings.TrimSpace(*installerSHA256), strings.TrimSpace(*bundleSHA256), strings.TrimSpace(*upgradeBundleSHA256), strings.TrimSpace(*policySHA256))
	return err
}
