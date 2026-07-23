// mesh-backup is an offline, create-only backup and restore utility. It never
// accepts secrets as command-line arguments and never emits secret material.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"mesh/internal/backupio"
)

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, backupio.New(), os.Getenv); err != nil {
		fmt.Fprintln(os.Stderr, "mesh-backup:", err)
		os.Exit(1)
	}
}

type environment func(string) string

func run(ctx context.Context, args []string, output io.Writer, operations backupio.Operations, getenv environment) error {
	if len(args) == 0 {
		return usageError()
	}
	if operations == nil || getenv == nil {
		return errors.New("backup command dependencies are unavailable")
	}
	var result any
	var err error
	switch args[0] {
	case "keygen":
		result, err = keygen(args[1:], operations)
	case "create":
		result, err = create(ctx, args[1:], operations, getenv)
	case "inspect":
		result, err = inspect(ctx, args[1:], operations)
	case "verify":
		result, err = verify(ctx, args[1:], operations)
	case "restore":
		result, err = restore(ctx, args[1:], operations)
	case "finalize-restore":
		result, err = finalizeRestore(ctx, args[1:], operations)
	default:
		return usageError()
	}
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write command result: %w", err)
	}
	return nil
}

func usageError() error {
	return errors.New("usage: mesh-backup <keygen|create|inspect|verify|restore|finalize-restore> [flags]")
}

func newFlagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func requireFlags(set *flag.FlagSet, values ...struct{ name, value string }) error {
	if set.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", set.Name())
	}
	for _, item := range values {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("--%s is required", item.name)
		}
	}
	return nil
}

func keygen(args []string, operations backupio.Operations) (backupio.KeygenResult, error) {
	set := newFlagSet("keygen")
	output := set.String("output", "", "new private backup key file")
	if err := set.Parse(args); err != nil {
		return backupio.KeygenResult{}, err
	}
	if err := requireFlags(set, struct{ name, value string }{"output", *output}); err != nil {
		return backupio.KeygenResult{}, err
	}
	return operations.Keygen(backupio.KeygenOptions{OutputPath: *output})
}

func create(ctx context.Context, args []string, operations backupio.Operations, getenv environment) (backupio.ArchiveResult, error) {
	set := newFlagSet("create")
	dataDir := set.String("data-dir", "", "stopped Mesh data directory")
	keyFile := set.String("key-file", "", "private backup key file")
	output := set.String("output", "", "new encrypted backup archive")
	if err := set.Parse(args); err != nil {
		return backupio.ArchiveResult{}, err
	}
	if err := requireFlags(set,
		struct{ name, value string }{"data-dir", *dataDir},
		struct{ name, value string }{"key-file", *keyFile},
		struct{ name, value string }{"output", *output},
	); err != nil {
		return backupio.ArchiveResult{}, err
	}
	return operations.Create(ctx, backupio.CreateOptions{
		DataDir: *dataDir, KeyFile: *keyFile, OutputPath: *output,
		MasterKey: getenv("MESH_MASTER_KEY"), AdminToken: getenv("MESH_ADMIN_TOKEN"),
	})
}

func archiveFlags(command string, args []string) (*flag.FlagSet, *string, *string, error) {
	set := newFlagSet(command)
	keyFile := set.String("key-file", "", "private backup key file")
	archive := set.String("archive", "", "encrypted backup archive")
	if err := set.Parse(args); err != nil {
		return nil, nil, nil, err
	}
	if err := requireFlags(set,
		struct{ name, value string }{"key-file", *keyFile},
		struct{ name, value string }{"archive", *archive},
	); err != nil {
		return nil, nil, nil, err
	}
	return set, keyFile, archive, nil
}

func inspect(ctx context.Context, args []string, operations backupio.Operations) (backupio.ArchiveResult, error) {
	_, keyFile, archive, err := archiveFlags("inspect", args)
	if err != nil {
		return backupio.ArchiveResult{}, err
	}
	return operations.Inspect(ctx, backupio.ArchiveOptions{KeyFile: *keyFile, ArchivePath: *archive})
}

func verify(ctx context.Context, args []string, operations backupio.Operations) (backupio.ArchiveResult, error) {
	_, keyFile, archive, err := archiveFlags("verify", args)
	if err != nil {
		return backupio.ArchiveResult{}, err
	}
	return operations.Verify(ctx, backupio.ArchiveOptions{KeyFile: *keyFile, ArchivePath: *archive})
}

func restore(ctx context.Context, args []string, operations backupio.Operations) (backupio.ArchiveResult, error) {
	set := newFlagSet("restore")
	keyFile := set.String("key-file", "", "private backup key file")
	archive := set.String("archive", "", "encrypted backup archive")
	targetDir := set.String("target-dir", "", "new restore target directory")
	expectedID := set.String("expect-backup-id", "", "exact authenticated backup ID")
	if err := set.Parse(args); err != nil {
		return backupio.ArchiveResult{}, err
	}
	if err := requireFlags(set,
		struct{ name, value string }{"key-file", *keyFile},
		struct{ name, value string }{"archive", *archive},
		struct{ name, value string }{"target-dir", *targetDir},
		struct{ name, value string }{"expect-backup-id", *expectedID},
	); err != nil {
		return backupio.ArchiveResult{}, err
	}
	return operations.Restore(ctx, backupio.RestoreOptions{
		KeyFile: *keyFile, ArchivePath: *archive, TargetDir: *targetDir, ExpectedBackupID: *expectedID,
	})
}

func finalizeRestore(ctx context.Context, args []string, operations backupio.Operations) (backupio.ArchiveResult, error) {
	set := newFlagSet("finalize-restore")
	targetDir := set.String("target-dir", "", "restore target directory with an incomplete marker")
	if err := set.Parse(args); err != nil {
		return backupio.ArchiveResult{}, err
	}
	if err := requireFlags(set, struct{ name, value string }{"target-dir", *targetDir}); err != nil {
		return backupio.ArchiveResult{}, err
	}
	return operations.FinalizeRestore(ctx, backupio.FinalizeRestoreOptions{TargetDir: *targetDir})
}
