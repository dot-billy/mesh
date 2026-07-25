package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"mesh/internal/backupio"
)

type fakeOperations struct {
	keygenOptions   backupio.KeygenOptions
	createOptions   backupio.CreateOptions
	archiveOptions  backupio.ArchiveOptions
	restoreOptions  backupio.RestoreOptions
	finalizeOptions backupio.FinalizeRestoreOptions
	command         string
	err             error
}

func (f *fakeOperations) Keygen(options backupio.KeygenOptions) (backupio.KeygenResult, error) {
	f.command, f.keygenOptions = "keygen", options
	return backupio.KeygenResult{Schema: "mesh-backup-command-result-v1", Status: "created", Path: options.OutputPath}, f.err
}
func (f *fakeOperations) Create(_ context.Context, options backupio.CreateOptions) (backupio.ArchiveResult, error) {
	f.command, f.createOptions = "create", options
	return fakeArchiveResult("created"), f.err
}
func (f *fakeOperations) Inspect(_ context.Context, options backupio.ArchiveOptions) (backupio.ArchiveResult, error) {
	f.command, f.archiveOptions = "inspect", options
	return fakeArchiveResult("inspected"), f.err
}
func (f *fakeOperations) Verify(_ context.Context, options backupio.ArchiveOptions) (backupio.ArchiveResult, error) {
	f.command, f.archiveOptions = "verify", options
	return fakeArchiveResult("verified"), f.err
}
func (f *fakeOperations) Restore(_ context.Context, options backupio.RestoreOptions) (backupio.ArchiveResult, error) {
	f.command, f.restoreOptions = "restore", options
	return fakeArchiveResult("restored"), f.err
}
func (f *fakeOperations) FinalizeRestore(_ context.Context, options backupio.FinalizeRestoreOptions) (backupio.ArchiveResult, error) {
	f.command, f.finalizeOptions = "finalize-restore", options
	return fakeArchiveResult("finalized"), f.err
}

func fakeArchiveResult(status string) backupio.ArchiveResult {
	return backupio.ArchiveResult{
		Schema: "mesh-backup-command-result-v1", Status: status,
		BackupID: strings.Repeat("a", 32), CreatedAt: time.Unix(1, 0).UTC(),
	}
}

func TestCreateWiresSecretsOnlyFromEnvironmentAndEmitsJSONWithoutSecrets(t *testing.T) {
	fake := &fakeOperations{}
	master := strings.Repeat("M", 43)
	admin := strings.Repeat("A", 43)
	getenv := func(name string) string {
		switch name {
		case "MESH_MASTER_KEY":
			return master
		case "MESH_ADMIN_TOKEN":
			return admin
		default:
			return ""
		}
	}
	var output bytes.Buffer
	err := run(context.Background(), []string{"create", "--data-dir", "/data", "--key-file", "/keys/backup", "--output", "/backups/one"}, &output, fake, getenv)
	if err != nil {
		t.Fatal(err)
	}
	if fake.command != "create" || fake.createOptions.MasterKey != master || fake.createOptions.AdminToken != admin {
		t.Fatalf("environment secrets were not wired: %+v", fake.createOptions)
	}
	if strings.Contains(output.String(), master) || strings.Contains(output.String(), admin) {
		t.Fatalf("success JSON leaked a secret: %s", output.String())
	}
	if !strings.HasPrefix(output.String(), `{"schema":"mesh-backup-command-result-v1","status":"created"`) || strings.Count(output.String(), "\n") != 1 {
		t.Fatalf("success output is not one JSON document: %q", output.String())
	}
}

func TestSecretFlagsAreNotAcceptedOrEchoed(t *testing.T) {
	secret := "DO-NOT-ECHO-THIS-SECRET"
	for _, flagName := range []string{"--master-key", "--admin-token", "--backup-key"} {
		t.Run(flagName, func(t *testing.T) {
			var output bytes.Buffer
			err := run(context.Background(), []string{"create", flagName, secret, "--data-dir", "/data", "--key-file", "/key", "--output", "/out"}, &output, &fakeOperations{}, func(string) string { return "" })
			if err == nil {
				t.Fatal("secret command-line flag was accepted")
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(output.String(), secret) || output.Len() != 0 {
				t.Fatalf("secret was echoed: error=%q output=%q", err, output.String())
			}
		})
	}
}

func TestCommandFlagContracts(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing-command", nil},
		{"unknown-command", []string{"unknown"}},
		{"missing-required", []string{"keygen"}},
		{"unknown-flag", []string{"inspect", "--unknown"}},
		{"positional", []string{"finalize-restore", "--target-dir", "/target", "extra"}},
		{"restore-missing-expected-id", []string{"restore", "--key-file", "/key", "--archive", "/archive", "--target-dir", "/target"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := run(context.Background(), test.args, &output, &fakeOperations{}, func(string) string { return "" }); err == nil {
				t.Fatal("invalid command was accepted")
			}
			if output.Len() != 0 {
				t.Fatalf("invalid command wrote success output: %q", output.String())
			}
		})
	}
}

func TestAllPublicCommandsForwardExactFileOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"keygen", []string{"keygen", "--output", "/key"}, "keygen"},
		{"inspect", []string{"inspect", "--key-file", "/key", "--archive", "/archive"}, "inspect"},
		{"verify", []string{"verify", "--key-file", "/key", "--archive", "/archive"}, "verify"},
		{"restore", []string{"restore", "--key-file", "/key", "--archive", "/archive", "--target-dir", "/target", "--expect-backup-id", strings.Repeat("a", 32)}, "restore"},
		{"finalize", []string{"finalize-restore", "--target-dir", "/target"}, "finalize-restore"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeOperations{}
			var output bytes.Buffer
			if err := run(context.Background(), test.args, &output, fake, func(string) string { return "" }); err != nil {
				t.Fatal(err)
			}
			if fake.command != test.want {
				t.Fatalf("forwarded %q, want %q", fake.command, test.want)
			}
		})
	}
}

func TestOperationErrorWritesNoSuccessJSON(t *testing.T) {
	secret := "SHOULD-NOT-APPEAR"
	fake := &fakeOperations{err: errors.New("operation failed")}
	var output bytes.Buffer
	err := run(context.Background(), []string{"keygen", "--output", "/key"}, &output, fake, func(string) string { return secret })
	if err == nil || output.Len() != 0 || strings.Contains(err.Error(), secret) {
		t.Fatalf("unexpected error behavior: err=%v output=%q", err, output.String())
	}
}
