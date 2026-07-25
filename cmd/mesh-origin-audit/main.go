// mesh-origin-audit proves that one external HTTPS route serves one exact
// locally inspected release-origin generation. Its receipt is courier evidence,
// never release authority.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"mesh/internal/originaudit"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, func() time.Time { return time.Now().UTC() }); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mesh-origin-audit:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, clock func() time.Time) error {
	flags := flag.NewFlagSet("mesh-origin-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	generation := flags.String("generation", "", "clean absolute inspected origin generation")
	origin := flags.String("origin", "", "canonical public HTTPS origin base URL without a path")
	caFile := flags.String("ca-file", "", "optional clean absolute PEM CA bundle (system roots when omitted)")
	timeout := flags.Duration("timeout", originaudit.DefaultTimeout, "positive complete-audit deadline up to one hour")
	receiptPath := flags.String("output", "-", "new canonical receipt path, or - for stdout only")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid origin audit arguments")
	}
	if *generation == "" || *origin == "" || *receiptPath == "" {
		return errors.New("--generation, --origin, and --output are required")
	}
	receipt, err := originaudit.Audit(context.Background(), originaudit.Config{
		GenerationPath: *generation,
		Origin:         *origin,
		CAFile:         *caFile,
		Timeout:        *timeout,
	}, clock)
	if err != nil {
		return err
	}
	raw, err := originaudit.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	if *receiptPath != "-" {
		if err := originaudit.WriteNewReceipt(*receiptPath, raw); err != nil {
			return err
		}
	}
	_, err = output.Write(raw)
	return err
}
