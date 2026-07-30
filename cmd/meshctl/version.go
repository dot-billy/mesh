package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"mesh/internal/buildinfo"
	"mesh/internal/darwincodesign"
)

func version(args []string) error {
	return versionTo(args, os.Stdout)
}

func versionTo(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("version does not accept positional arguments")
	}
	info, err := buildinfo.Current()
	if err != nil {
		return err
	}
	if *jsonOutput {
		policySHA := ""
		if info.OS == "darwin" && darwincodesign.Identity != darwincodesign.DevelopmentPolicy {
			policy, err := darwincodesign.LoadPolicy()
			if err != nil {
				return fmt.Errorf("load compiled Darwin code-signing policy: %w", err)
			}
			policySHA = policy.SHA256
		}
		encoder := json.NewEncoder(output)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(struct {
			buildinfo.Info
			DarwinCodeSigningPolicySHA256 string `json:"darwin_code_signing_policy_sha256"`
		}{
			Info: info, DarwinCodeSigningPolicySHA256: policySHA,
		})
	}
	_, err = fmt.Fprintf(output, "meshctl %s (%s, built %s, %s/%s, security floor %d)\n", info.Version, info.Commit, info.BuildTime, info.OS, info.Arch, info.SecurityFloor)
	return err
}
