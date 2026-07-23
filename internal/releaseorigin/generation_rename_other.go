//go:build !linux

package releaseorigin

import "errors"

func renameGenerationNoReplace(_, _, _ string) error {
	return errors.New("durable release origin generation publication requires Linux renameat2(RENAME_NOREPLACE)")
}
