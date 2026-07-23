// mesh-origin-runtime-verify binds prior signature and image-security receipts
// plus an immutable origin generation to one exact healthy Docker runtime.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"mesh/internal/origindeploy"
	"mesh/internal/releaseorigin"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, func() time.Time { return time.Now().UTC() }, origindeploy.ExecRunner{}, releaseorigin.InspectGeneration); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "mesh-origin-runtime-verify:", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer, clock func() time.Time, runner origindeploy.Runner, inspector origindeploy.GenerationInspector) error {
	flags := flag.NewFlagSet("mesh-origin-runtime-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	imageReceipt := flags.String("image-receipt", "", "clean absolute canonical image-verification receipt")
	securityReceipt := flags.String("security-receipt", "", "clean absolute canonical image-security receipt")
	composeConfig := flags.String("compose-config", "", "clean absolute rendered production Compose JSON")
	generation := flags.String("generation", "", "clean absolute inspected immutable origin generation")
	containerID := flags.String("container-id", "", "exact 64-character running origin container ID")
	dockerPath := flags.String("docker", "/usr/bin/docker", "clean absolute Docker executable")
	dockerSocket := flags.String("docker-socket", "/run/docker.sock", "clean absolute local Docker Unix socket")
	timeout := flags.Duration("timeout", origindeploy.DefaultTimeout, "positive complete verification deadline up to five minutes")
	receiptPath := flags.String("output", "-", "new canonical receipt path, or - for stdout only")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid origin runtime verification arguments")
	}
	if *imageReceipt == "" || *securityReceipt == "" || *composeConfig == "" || *generation == "" || *containerID == "" ||
		*dockerPath == "" || *dockerSocket == "" || *receiptPath == "" {
		return errors.New("--image-receipt, --security-receipt, --compose-config, --generation, --container-id, --docker, --docker-socket, and --output are required")
	}
	receipt, err := origindeploy.Verify(context.Background(), origindeploy.Config{
		ImageReceipt: *imageReceipt, SecurityReceipt: *securityReceipt, ComposeConfig: *composeConfig, Generation: *generation,
		ContainerID: *containerID, DockerPath: *dockerPath, DockerSocket: *dockerSocket, Timeout: *timeout,
	}, clock, runner, inspector)
	if err != nil {
		return err
	}
	raw, err := origindeploy.EncodeReceipt(receipt)
	if err != nil {
		return err
	}
	if *receiptPath != "-" {
		if err := origindeploy.WriteNewReceipt(*receiptPath, raw); err != nil {
			return err
		}
	}
	_, err = output.Write(raw)
	return err
}
