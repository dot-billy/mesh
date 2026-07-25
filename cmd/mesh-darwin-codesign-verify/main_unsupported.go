//go:build !darwin

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "mesh-darwin-codesign-verify: native Darwin execution is required")
	os.Exit(1)
}
