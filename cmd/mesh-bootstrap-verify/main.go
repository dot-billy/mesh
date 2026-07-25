// mesh-bootstrap-verify authenticates a separately distributed first
// mesh-install binary. It never signs, downloads, executes, extracts, installs,
// or mutates software.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"mesh/internal/bootstrapverify"
	"mesh/internal/buildinfo"
)

const verifierUsage = "usage: mesh-bootstrap-verify --root <root-v1.json> (--expected-root-sha256 <independent-root-digest> | --handoff <bootstrap-handoff.json> (--expected-handoff-sha256 <independent-handoff-digest> | --handoff-anchor <independently-transferred-anchor.json>)) --manifest <bootstrap.json> --signature <root-signature.json> [--signature ...] --installer <platform-installer> [--now <UTC-RFC3339>]"

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(args []string, output, diagnostics io.Writer) int {
	err := verify(args, output, diagnostics)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(diagnostics, "mesh-bootstrap-verify:", err)
		return 1
	}
	return 0
}

func verify(args []string, output, diagnostics io.Writer) error {
	// Parse the sole compiled build identity on every invocation. Development
	// builds use the explicit development sentinel; independently distributed
	// production packages carry the canonical linker-set frame that offline
	// packaging inspects from these same binary bytes.
	if _, err := buildinfo.Current(); err != nil {
		return fmt.Errorf("compiled verifier identity: %w", err)
	}
	flags := flag.NewFlagSet("mesh-bootstrap-verify", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	flags.Usage = func() {
		fmt.Fprintln(diagnostics, verifierUsage)
		flags.PrintDefaults()
	}
	rootPath := flags.String("root", "", "canonical version-1 root obtained with the bootstrap materials")
	expectedRootSHA := flags.String("expected-root-sha256", "", "root digest authenticated through an independent channel")
	handoffPath := flags.String("handoff", "", "canonical bootstrap handoff obtained with the courier materials")
	expectedHandoffSHA := flags.String("expected-handoff-sha256", "", "handoff digest authenticated through an independent channel")
	handoffAnchorPath := flags.String("handoff-anchor", "", "canonical bootstrap anchor transferred independently of the release origin")
	manifestPath := flags.String("manifest", "", "canonical root-authorized bootstrap manifest")
	installerPath := flags.String("installer", "", "downloaded platform installer to authenticate without executing")
	nowText := flags.String("now", "", "optional fixed canonical UTC RFC3339 verification time")
	var signaturePaths repeatedFlag
	flags.Var(&signaturePaths, "signature", "detached root-role bootstrap signature (repeat)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not accepted")
	}
	if strings.TrimSpace(*rootPath) == "" || strings.TrimSpace(*manifestPath) == "" || strings.TrimSpace(*installerPath) == "" || len(signaturePaths) == 0 {
		return errors.New("--root, --manifest, --installer, and at least one --signature are required")
	}
	directRootMode := strings.TrimSpace(*expectedRootSHA) != ""
	handoffProvided := strings.TrimSpace(*handoffPath) != ""
	directHandoffMode := strings.TrimSpace(*expectedHandoffSHA) != ""
	anchorHandoffMode := strings.TrimSpace(*handoffAnchorPath) != ""
	handoffMode := handoffProvided && directHandoffMode != anchorHandoffMode
	if (directRootMode && (handoffProvided || directHandoffMode || anchorHandoffMode)) || (!directRootMode && !handoffMode) {
		return errors.New("use exactly one trust anchor: --expected-root-sha256, --handoff with --expected-handoff-sha256, or --handoff with --handoff-anchor")
	}
	now := time.Now().UTC()
	if *nowText != "" {
		parsed, err := parseVerificationTime(*nowText)
		if err != nil {
			return err
		}
		now = parsed
	}
	var result bootstrapverify.Result
	var err error
	if handoffMode {
		result, err = bootstrapverify.VerifyHandoffFiles(bootstrapverify.HandoffFileInput{
			HandoffPath: *handoffPath, ExpectedHandoffSHA256: *expectedHandoffSHA, AnchorPath: *handoffAnchorPath, RootPath: *rootPath,
			ManifestPath: *manifestPath, SignaturePaths: append([]string(nil), signaturePaths...),
			InstallerPath: *installerPath, Now: now,
		})
	} else {
		result, err = bootstrapverify.VerifyFiles(bootstrapverify.FileInput{
			RootPath: *rootPath, ExpectedRootSHA256: *expectedRootSHA,
			ManifestPath: *manifestPath, SignaturePaths: append([]string(nil), signaturePaths...),
			InstallerPath: *installerPath, Now: now,
		})
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("encode bootstrap verification result: %w", err)
	}
	return nil
}

func parseVerificationTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("--now must be canonical UTC RFC3339 without fractional seconds")
	}
	return parsed.UTC(), nil
}

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("flag value cannot be empty")
	}
	*values = append(*values, value)
	return nil
}
