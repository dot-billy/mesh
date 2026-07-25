// mesh-origin-image-verify authenticates one exact digest-pinned release-origin
// container image with an independently provisioned Cosign public key.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"mesh/internal/originimage"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, func() time.Time { return time.Now().UTC() }, originimage.ExecRunner{}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mesh-origin-image-verify:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, clock func() time.Time, runner originimage.Runner) error {
	flags := flag.NewFlagSet("mesh-origin-image-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	image := flags.String("image", "", "exact registry/repository@sha256:<digest> origin image")
	publicKey := flags.String("key", "", "clean absolute independently provisioned Cosign public key")
	cosignPath := flags.String("cosign", "/usr/local/bin/cosign", "clean absolute Cosign executable")
	timeout := flags.Duration("timeout", originimage.DefaultTimeout, "positive complete verification deadline up to one hour")
	receiptPath := flags.String("output", "-", "new canonical receipt path, or - for stdout only")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid origin image verification arguments")
	}
	if *image == "" || *publicKey == "" || *cosignPath == "" || *receiptPath == "" {
		return errors.New("--image, --key, --cosign, and --output are required")
	}
	receipt, err := originimage.Verify(context.Background(), originimage.Config{
		Image: *image, PublicKey: *publicKey, CosignPath: *cosignPath, Timeout: *timeout,
	}, clock, runner)
	if err != nil {
		return err
	}
	raw, err := originimage.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	if *receiptPath != "-" {
		if err := originimage.WriteNewReceipt(*receiptPath, raw); err != nil {
			return err
		}
	}
	_, err = output.Write(raw)
	return err
}
