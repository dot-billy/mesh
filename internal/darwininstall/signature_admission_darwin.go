//go:build darwin

package darwininstall

import (
	"errors"
	"fmt"
	"path/filepath"

	"mesh/internal/darwinbundle"
	"mesh/internal/darwincodesign"
)

// verifyDarwinReleaseSignatures applies the build's immutable Developer ID
// policy only after the complete release tree has been authenticated against
// threshold-signed bundle metadata. No package field can select Team ID,
// identifier, requirement language, or codesign arguments.
func verifyDarwinReleaseSignatures(releaseRoot string, inspection darwinbundle.CandidateInspection) error {
	if err := darwinbundle.ValidateCandidateInspection(inspection); err != nil {
		return err
	}
	if !cleanDarwinInstallPath(releaseRoot) ||
		filepath.Base(releaseRoot) == "bin" {
		return errors.New("Darwin code-signature admission requires one canonical release root")
	}
	results, err := darwincodesign.VerifyRelease(releaseRoot)
	if err != nil {
		return err
	}
	if len(results) != 3 {
		return errors.New("Darwin code-signature admission did not verify all three executables")
	}
	policySHA := results[0].PolicySHA256
	teamID := results[0].TeamID
	for _, result := range results {
		if result.PolicySHA256 != policySHA || result.TeamID != teamID {
			return errors.New("Darwin release executables do not share one compiled code-signing authority")
		}
	}
	if policySHA == "" || teamID == "" {
		return fmt.Errorf("Darwin code-signature admission returned an empty policy identity")
	}
	return nil
}
