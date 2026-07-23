//go:build !linux

package verifierbundle

import "errors"

func snapshotRegularFile(string, int64) ([]byte, error) {
	return nil, errors.New("bootstrap verifier input snapshot requires Linux")
}
