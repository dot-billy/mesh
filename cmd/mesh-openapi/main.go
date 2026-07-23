// Command mesh-openapi prints the canonical Mesh OpenAPI contract. The public
// documentation generator uses this command so the served and checked-in
// contracts always originate from the same typed route catalog.
package main

import (
	"fmt"
	"os"

	"mesh/internal/httpapi"
)

func main() {
	document, err := httpapi.CanonicalOpenAPI()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(document); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
