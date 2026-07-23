//go:build !linux && !darwin

package postgresconfig

func readPrivateFile(string, func()) ([]byte, error) {
	return nil, errUnsupported
}
