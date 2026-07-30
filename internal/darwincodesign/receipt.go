package darwincodesign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	ReceiptSchema        = "mesh-darwin-codesign-receipt-v2"
	MaximumReceiptSize   = 24 << 10
	maximumReceiptAge    = 24 * time.Hour
	maximumReceiptFuture = 5 * time.Minute
)

var receiptFileContract = []struct {
	path string
	role string
}{
	{path: "mesh-install", role: MeshInstallRole},
	{path: "bin/meshctl", role: MeshctlRole},
	{path: "bin/nebula", role: NebulaRole},
	{path: "bin/nebula-cert", role: NebulaCertRole},
}

type FileEvidence struct {
	Identifier string `json:"identifier"`
	Path       string `json:"path"`
	Role       string `json:"role"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
}

type Receipt struct {
	Architecture string         `json:"architecture"`
	Files        []FileEvidence `json:"files"`
	PolicySHA256 string         `json:"policy_sha256"`
	Schema       string         `json:"schema"`
	TeamID       string         `json:"team_id"`
	VerifiedAt   string         `json:"verified_at"`
}

type ArtifactIdentity struct {
	Path   string
	SHA256 string
	Size   int64
}

func EncodeReceipt(receipt Receipt) ([]byte, error) {
	if err := validateReceipt(receipt); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("encode Darwin code-signing receipt: %w", err)
	}
	if len(raw)+1 > MaximumReceiptSize {
		return nil, errors.New("Darwin code-signing receipt exceeds its size bound")
	}
	return append(raw, '\n'), nil
}

func ParseReceipt(raw []byte) (Receipt, error) {
	if len(raw) < 2 || len(raw) > MaximumReceiptSize {
		return Receipt{}, errors.New("Darwin code-signing receipt is empty or oversized")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("decode Darwin code-signing receipt: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Receipt{}, errors.New("Darwin code-signing receipt contains trailing data")
	}
	if err := validateReceipt(receipt); err != nil {
		return Receipt{}, err
	}
	canonical, err := EncodeReceipt(receipt)
	if err != nil {
		return Receipt{}, err
	}
	if !bytes.Equal(canonical, raw) {
		return Receipt{}, errors.New("Darwin code-signing receipt must be canonical compact JSON followed by one LF")
	}
	return receipt, nil
}

func (receipt Receipt) Match(now time.Time, policy Policy, arch string, artifacts []ArtifactIdentity) error {
	if err := receipt.matchAuthority(now, policy, arch); err != nil {
		return err
	}
	return receipt.matchArtifacts(artifacts, []string{
		"bin/meshctl", "bin/nebula", "bin/nebula-cert",
	})
}

// MatchBootstrap proves that the same native receipt covers the signed
// mesh-install binary admitted into the protected flat package.
func (receipt Receipt) MatchBootstrap(now time.Time, policy Policy, arch string, artifact ArtifactIdentity) error {
	if err := receipt.matchAuthority(now, policy, arch); err != nil {
		return err
	}
	return receipt.matchArtifacts([]ArtifactIdentity{artifact}, []string{"mesh-install"})
}

func (receipt Receipt) matchAuthority(now time.Time, policy Policy, arch string) error {
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	for _, role := range []string{MeshInstallRole, MeshctlRole, NebulaRole, NebulaCertRole} {
		if _, err := policy.Requirement(role); err != nil {
			return err
		}
	}
	if !digestPattern.MatchString(policy.SHA256) {
		return errors.New("Darwin code-signing policy digest is invalid")
	}
	verifiedAt, _ := time.Parse(time.RFC3339, receipt.VerifiedAt)
	now = now.UTC()
	if now.IsZero() || verifiedAt.After(now.Add(maximumReceiptFuture)) {
		return errors.New("Darwin code-signing receipt verification time is in the future")
	}
	if now.Sub(verifiedAt) > maximumReceiptAge {
		return errors.New("Darwin code-signing receipt is older than 24 hours")
	}
	if receipt.PolicySHA256 != policy.SHA256 || receipt.TeamID != policy.TeamID ||
		receipt.Architecture != arch {
		return errors.New("Darwin code-signing receipt policy or architecture differs from the release")
	}
	for _, file := range receipt.Files {
		identifier, _ := policy.Identifier(file.Role)
		if file.Identifier != identifier {
			return fmt.Errorf("Darwin code-signing receipt identifier differs for role %q", file.Role)
		}
	}
	return nil
}

func (receipt Receipt) matchArtifacts(artifacts []ArtifactIdentity, wantedPaths []string) error {
	wanted := append([]ArtifactIdentity(nil), artifacts...)
	sort.Slice(wanted, func(left, right int) bool { return wanted[left].Path < wanted[right].Path })
	expectedPaths := append([]string(nil), wantedPaths...)
	sort.Strings(expectedPaths)
	if len(wanted) != len(expectedPaths) {
		return errors.New("Darwin code-signing receipt artifact set is incomplete")
	}
	files := make(map[string]FileEvidence, len(receipt.Files))
	for _, file := range receipt.Files {
		files[file.Path] = file
	}
	for index, artifact := range wanted {
		if artifact.Path != expectedPaths[index] {
			return errors.New("Darwin code-signing receipt artifact paths differ from the required set")
		}
		file, found := files[artifact.Path]
		if !found || artifact.Size != file.Size || artifact.SHA256 != file.SHA256 {
			return fmt.Errorf("Darwin code-signing receipt differs from signed artifact %q", artifact.Path)
		}
	}
	return nil
}

func validateReceipt(receipt Receipt) error {
	if receipt.Schema != ReceiptSchema ||
		(receipt.Architecture != "amd64" && receipt.Architecture != "arm64") ||
		!digestPattern.MatchString(receipt.PolicySHA256) ||
		!teamIDPattern.MatchString(receipt.TeamID) {
		return errors.New("Darwin code-signing receipt schema, architecture, policy, or Team ID is invalid")
	}
	verifiedAt, err := time.Parse(time.RFC3339, receipt.VerifiedAt)
	if err != nil || verifiedAt.UTC().Format(time.RFC3339) != receipt.VerifiedAt {
		return errors.New("Darwin code-signing receipt time is not canonical UTC RFC3339")
	}
	if len(receipt.Files) != len(receiptFileContract) {
		return errors.New("Darwin code-signing receipt must contain exactly four signed files")
	}
	seenIdentifiers := make(map[string]struct{}, len(receiptFileContract))
	for index, file := range receipt.Files {
		want := receiptFileContract[index]
		if file.Path != want.path || file.Role != want.role ||
			file.Size < 512 || file.Size > 132<<20 ||
			!digestPattern.MatchString(file.SHA256) ||
			!identifierPattern.MatchString(file.Identifier) {
			return fmt.Errorf("Darwin code-signing receipt file %d is invalid or unordered", index)
		}
		if _, duplicate := seenIdentifiers[file.Identifier]; duplicate {
			return errors.New("Darwin code-signing receipt identifiers must be distinct")
		}
		seenIdentifiers[file.Identifier] = struct{}{}
	}
	return nil
}
