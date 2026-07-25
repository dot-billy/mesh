// mesh-postgres-load-smoke is a test-only driver for the bounded PostgreSQL
// intended-workload gate. It is built into a disposable private workspace by
// scripts/postgres-load-soak-smoke.sh and is not part of the release binaries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"mesh/internal/postgresloadgate"
)

type commandFlags struct {
	replicaOne           string
	replicaTwo           string
	publicOrigin         string
	networkID            string
	adminTokenFile       string
	postgresDSNFile      string
	generatedSecretsFile string
	reportFile           string
	expectedReportFile   string
}

func parseFlags(name string, arguments []string, verify bool) (commandFlags, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(os.Stderr)
	var values commandFlags
	set.StringVar(&values.replicaOne, "replica-one", "", "first real mesh-server origin")
	set.StringVar(&values.replicaTwo, "replica-two", "", "second real mesh-server origin")
	set.StringVar(&values.publicOrigin, "public-origin", "", "configured browser public origin")
	set.StringVar(&values.networkID, "network-id", "", "imported source network ID")
	set.StringVar(&values.adminTokenFile, "admin-token-file", "", "private administrator token file")
	set.StringVar(&values.postgresDSNFile, "postgres-dsn-file", "", "private PostgreSQL DSN file")
	set.StringVar(&values.generatedSecretsFile, "generated-secrets-file", "", "private generated-secret capture")
	set.StringVar(&values.reportFile, "report", "", "create-only private JSON report")
	if verify {
		set.StringVar(&values.expectedReportFile, "expected-report", "", "successful pre-restart load report")
	}
	if err := set.Parse(arguments); err != nil {
		return commandFlags{}, err
	}
	if set.NArg() != 0 {
		return commandFlags{}, errors.New("positional arguments are not supported")
	}
	for label, value := range map[string]string{
		"--replica-one":            values.replicaOne,
		"--replica-two":            values.replicaTwo,
		"--public-origin":          values.publicOrigin,
		"--network-id":             values.networkID,
		"--admin-token-file":       values.adminTokenFile,
		"--postgres-dsn-file":      values.postgresDSNFile,
		"--generated-secrets-file": values.generatedSecretsFile,
		"--report":                 values.reportFile,
	} {
		if value == "" {
			return commandFlags{}, fmt.Errorf("%s is required", label)
		}
	}
	if verify && values.expectedReportFile == "" {
		return commandFlags{}, errors.New("--expected-report is required")
	}
	paths := []string{values.adminTokenFile, values.postgresDSNFile, values.generatedSecretsFile, values.reportFile}
	if verify {
		paths = append(paths, values.expectedReportFile)
	}
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return commandFlags{}, errors.New("all file paths must be clean and absolute")
		}
		if _, duplicate := seen[path]; duplicate {
			return commandFlags{}, errors.New("input and output files must be distinct")
		}
		seen[path] = struct{}{}
	}
	return values, nil
}

func (values commandFlags) config() postgresloadgate.Config {
	return postgresloadgate.Config{
		Replicas:             [2]string{values.replicaOne, values.replicaTwo},
		PublicOrigin:         values.publicOrigin,
		NetworkID:            values.networkID,
		AdminTokenFile:       values.adminTokenFile,
		PostgresDSNFile:      values.postgresDSNFile,
		GeneratedSecretsFile: values.generatedSecretsFile,
	}
}

func runCommand(ctx context.Context, arguments []string) error {
	values, err := parseFlags("run", arguments, false)
	if err != nil {
		return err
	}
	report, runErr := postgresloadgate.Run(ctx, values.config())
	if err := postgresloadgate.WriteJSONExclusive(values.reportFile, report); err != nil {
		return err
	}
	if runErr != nil {
		return fmt.Errorf("bounded load/soak gate failed: %w", runErr)
	}
	return nil
}

func verifyCommand(ctx context.Context, arguments []string) error {
	values, err := parseFlags("verify", arguments, true)
	if err != nil {
		return err
	}
	expected, err := postgresloadgate.ReadReport(values.expectedReportFile)
	if err != nil {
		return err
	}
	if err := postgresloadgate.VerifyReportOperations(expected); err != nil {
		return err
	}
	verification, verifyErr := postgresloadgate.VerifyRestart(ctx, values.config(), expected)
	if verifyErr != nil {
		verification.Error = verifyErr.Error()
	}
	if err := postgresloadgate.WriteJSONExclusive(values.reportFile, verification); err != nil {
		return err
	}
	if verifyErr != nil {
		return fmt.Errorf("restart verification failed: %w", verifyErr)
	}
	return nil
}

func execute(ctx context.Context, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: mesh-postgres-load-smoke <run|verify> [flags]")
	}
	switch arguments[0] {
	case "run":
		return runCommand(ctx, arguments[1:])
	case "verify":
		return verifyCommand(ctx, arguments[1:])
	default:
		return fmt.Errorf("unsupported command %q", arguments[0])
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}
