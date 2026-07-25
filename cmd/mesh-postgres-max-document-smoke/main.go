//go:build linux && postgresmaxdocgate

// mesh-postgres-max-document-smoke is a test-only driver compiled solely by
// scripts/postgres-max-document-smoke.sh. It is absent from release builds.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"mesh/internal/postgresmaxdocgate"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), postgresmaxdocgate.MaximumGateDuration)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-postgres-max-document-smoke:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer) error {
	if ctx == nil || output == nil || len(args) == 0 {
		return usageError()
	}
	var result any
	var err error
	switch args[0] {
	case "generate":
		result, err = generate(ctx, args[1:])
	case "verify":
		result, err = verify(ctx, args[1:])
	case "mutate":
		result, err = mutate(ctx, args[1:])
	default:
		return usageError()
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return errors.New("write maximum-document report failed")
	}
	return nil
}

func usageError() error {
	return errors.New("usage: mesh-postgres-max-document-smoke <generate|verify|mutate> [flags]")
}

func flagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func generate(ctx context.Context, args []string) (postgresmaxdocgate.FixtureMetadata, error) {
	set := flagSet("generate")
	output := set.String("output-dir", "", "private empty fixture directory")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *output == "" {
		return postgresmaxdocgate.FixtureMetadata{}, errors.New("generate requires --output-dir")
	}
	return postgresmaxdocgate.Generate(ctx, postgresmaxdocgate.GenerateOptions{OutputDirectory: *output})
}

func verify(ctx context.Context, args []string) (postgresmaxdocgate.DatabaseReport, error) {
	set := flagSet("verify")
	dsn := set.String("postgres-dsn-file", "", "private PostgreSQL DSN file")
	metadata := set.String("metadata", "", "fixture metadata file")
	backupID := set.String("backup-id", "", "authenticated backup ID")
	phase := set.String("phase", "", "initial or terminal")
	allowLocal := set.Bool("allow-local-plaintext-postgres", false, "allow numeric loopback plaintext PostgreSQL")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *dsn == "" || *metadata == "" || *backupID == "" || *phase == "" {
		return postgresmaxdocgate.DatabaseReport{}, errors.New("verify requires DSN, metadata, backup ID, and phase")
	}
	return postgresmaxdocgate.VerifyDatabase(ctx, postgresmaxdocgate.VerifyOptions{
		DSNFile: *dsn, MetadataFile: *metadata, BackupID: *backupID,
		AllowLocalPlaintext: *allowLocal, Phase: *phase,
	})
}

func mutate(ctx context.Context, args []string) (postgresmaxdocgate.MutationReport, error) {
	set := flagSet("mutate")
	dsn := set.String("postgres-dsn-file", "", "private PostgreSQL DSN file")
	metadata := set.String("metadata", "", "fixture metadata file")
	backupID := set.String("backup-id", "", "authenticated backup ID")
	serverURL := set.String("server-url", "", "loopback Mesh server origin")
	allowLocal := set.Bool("allow-local-plaintext-postgres", false, "allow numeric loopback plaintext PostgreSQL")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *dsn == "" || *metadata == "" || *backupID == "" || *serverURL == "" {
		return postgresmaxdocgate.MutationReport{}, errors.New("mutate requires DSN, metadata, backup ID, and server URL")
	}
	return postgresmaxdocgate.Mutate(ctx, postgresmaxdocgate.MutateOptions{
		DSNFile: *dsn, MetadataFile: *metadata, BackupID: *backupID, ServerURL: *serverURL,
		AllowLocalPlaintext: *allowLocal,
	})
}
