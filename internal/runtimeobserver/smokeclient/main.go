// Command smokeclient is a source-only integration helper for exercising the
// fixed production runtime-observer endpoint. It is not installed by Mesh.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"

	"mesh/internal/runtimeobserver"
)

type observer interface {
	Observe(context.Context, runtimeobserver.ValidationContext) (runtimeobserver.Snapshot, error)
}

type addresses []string

func (values *addresses) String() string { return strings.Join(*values, ",") }

func (values *addresses) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, runtimeobserver.Client{}); err != nil {
		fmt.Fprintln(os.Stderr, "runtime-observer-smokeclient:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, output io.Writer, client observer) error {
	flags := flag.NewFlagSet("runtime-observer-smokeclient", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	networkValue := flags.String("network", "", "canonical IPv4 overlay prefix")
	var lighthouseValues addresses
	flags.Var(&lighthouseValues, "lighthouse", "expected lighthouse IPv4 address; repeat as needed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("runtime-observer-smokeclient does not accept positional arguments")
	}
	if ctx == nil || output == nil || client == nil || strings.TrimSpace(*networkValue) == "" {
		return errors.New("--network and a usable observer are required")
	}
	network, err := netip.ParsePrefix(*networkValue)
	if err != nil || !network.Addr().Is4() || network != network.Masked() || network.String() != *networkValue {
		return errors.New("--network must be a canonical IPv4 prefix")
	}
	lighthouses := make([]netip.Addr, 0, len(lighthouseValues))
	for _, raw := range lighthouseValues {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !address.Is4() || address.String() != raw {
			return errors.New("--lighthouse must be a canonical IPv4 address")
		}
		lighthouses = append(lighthouses, address)
	}
	validation, err := runtimeobserver.NewValidationContext(network, lighthouses)
	if err != nil {
		return errors.New("observer topology is invalid")
	}
	snapshot, err := client.Observe(ctx, validation)
	if err != nil {
		return fmt.Errorf("observe fixed runtime endpoint: %w", err)
	}
	if _, err := runtimeobserver.EncodeSnapshotLine(snapshot, snapshot.Nonce, validation); err != nil {
		return errors.New("observer returned an invalid snapshot")
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(snapshot); err != nil {
		return fmt.Errorf("encode accepted snapshot: %w", err)
	}
	return nil
}
