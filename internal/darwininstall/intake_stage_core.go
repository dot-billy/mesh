package darwininstall

import (
	"errors"
	"fmt"
	"strings"
)

func DarwinCandidateInstalledID(candidate VerifiedDarwinCandidate) string {
	if err := validateVerifiedDarwinCandidate(candidate); err != nil {
		return ""
	}
	return fmt.Sprintf("e%020d-s%020d-r%s-a%s", candidate.ReleaseEpoch, candidate.Sequence,
		candidate.ReleaseManifestSHA256[:16], candidate.Artifact.SHA256[:16])
}

func darwinAcceptedStageName(candidate VerifiedDarwinCandidate) (string, error) {
	installedID := DarwinCandidateInstalledID(candidate)
	if installedID == "" || !darwinDigestPattern.MatchString(candidate.ChannelManifestSHA256) {
		return "", errors.New("Darwin accepted intake cannot derive a canonical stage identity")
	}
	name := ".stage-" + installedID + "-" + candidate.ChannelManifestSHA256[:32]
	if !darwinStageNamePattern.MatchString(name) || !strings.HasPrefix(name, ".stage-"+installedID+"-") {
		return "", errors.New("derived Darwin accepted-intake stage name is invalid")
	}
	return name, nil
}
