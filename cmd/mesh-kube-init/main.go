package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"mesh/internal/kubeinit"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mesh-kube-init:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	var options kubeinit.Options
	flags := flag.NewFlagSet("mesh-kube-init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.CredentialsSourceDir, "credentials-source-dir", "", "projected credentials volume root")
	flags.StringVar(&options.TLSSourceDir, "tls-source-dir", "", "projected TLS volume root")
	flags.StringVar(&options.IdentitySourceDir, "identity-source-dir", "", "optional projected identity volume root")
	flags.StringVar(&options.PostgresSourceDir, "postgres-source-dir", "", "optional projected PostgreSQL volume root")
	flags.StringVar(&options.OutputRoot, "output-root", "", "shared emptyDir publication root")
	flags.StringVar(&options.DataDir, "data-dir", "", "optional JSON persistent-data mount")
	flags.StringVar(&options.TLSServerName, "tls-server-name", "", "expected TLS certificate DNS name or IP")
	flags.IntVar(&options.RuntimeUID, "runtime-uid", 65532, "non-root Mesh runtime UID")
	flags.IntVar(&options.RuntimeGID, "runtime-gid", 65532, "non-root Mesh runtime GID")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid arguments")
	}
	return kubeinit.Run(options)
}
