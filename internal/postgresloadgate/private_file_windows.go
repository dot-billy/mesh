//go:build !linux && !darwin

package postgresloadgate

import "errors"

func readPrivateCanonicalLine(_, _ string) (string, error) {
	return "", errors.New("private load-gate credential files are unsupported on Windows")
}
