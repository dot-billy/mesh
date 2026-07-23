package nebulaobserverartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	darwinassets "mesh/third_party/nebula-darwin-runtime"
	observerassets "mesh/third_party/nebula-observer"
)

const DarwinManifestSchema = "mesh.nebula-darwin-runtime-stage.v1"

type darwinBuildPolicy struct {
	Schema                 string       `json:"schema"`
	BaseObserverLockSHA256 string       `json:"base_observer_lock_sha256"`
	Targets                []TargetLock `json:"targets"`
}

var (
	darwinOnce   sync.Once
	darwinPolicy darwinBuildPolicy
	darwinDigest string
	darwinErr    error
)

func embeddedDarwinPolicy() (darwinBuildPolicy, string, error) {
	darwinOnce.Do(func() {
		raw := darwinassets.BuildLock()
		darwinErr = decodeStrict(raw, &darwinPolicy)
		if darwinErr != nil {
			darwinErr = fmt.Errorf("invalid Darwin runtime build lock: %w", darwinErr)
			return
		}
		canonical, err := json.MarshalIndent(darwinPolicy, "", "  ")
		if err != nil {
			darwinErr = fmt.Errorf("encode Darwin runtime build lock: %w", err)
			return
		}
		canonical = append(canonical, '\n')
		if !bytes.Equal(raw, canonical) {
			darwinErr = errors.New("Darwin runtime build lock is not canonically encoded")
			return
		}
		base := sha256.Sum256(observerassets.BuildLock())
		if darwinPolicy.Schema != "mesh.nebula-darwin-runtime-build-lock.v1" ||
			darwinPolicy.BaseObserverLockSHA256 != hex.EncodeToString(base[:]) {
			darwinErr = errors.New("Darwin runtime build lock does not bind the embedded observer source policy")
			return
		}
		if len(darwinPolicy.Targets) != 2 {
			darwinErr = errors.New("Darwin runtime build lock must contain exactly two targets")
			return
		}
		for index, arch := range []string{"amd64", "arm64"} {
			target := darwinPolicy.Targets[index]
			if target.OS != "darwin" || target.Arch != arch || len(target.Entries) != 2 {
				darwinErr = fmt.Errorf("Darwin runtime target %d is not exact darwin/%s policy", index, arch)
				return
			}
			for entryIndex, expected := range []struct{ name, main string }{
				{"nebula", lockedModule + "/cmd/nebula"},
				{"nebula-cert", lockedModule + "/cmd/nebula-cert"},
			} {
				entry := target.Entries[entryIndex]
				if entry.Name != expected.name || entry.MainPath != expected.main || entry.Mode != 0o555 ||
					entry.Size <= 0 || entry.Size > maximumBinarySize || !lowerHex(entry.SHA256) {
					darwinErr = fmt.Errorf("Darwin runtime target %s entry %d is invalid", arch, entryIndex)
					return
				}
			}
		}
		digest := sha256.Sum256(raw)
		darwinDigest = hex.EncodeToString(digest[:])
	})
	clone := darwinPolicy
	clone.Targets = make([]TargetLock, len(darwinPolicy.Targets))
	for index, target := range darwinPolicy.Targets {
		clone.Targets[index] = cloneTarget(target)
	}
	return clone, darwinDigest, darwinErr
}

func selectDarwinTarget(arch string) (TargetLock, string, error) {
	policy, digest, err := embeddedDarwinPolicy()
	if err != nil {
		return TargetLock{}, "", err
	}
	for _, target := range policy.Targets {
		if target.Arch == arch {
			return cloneTarget(target), digest, nil
		}
	}
	return TargetLock{}, "", fmt.Errorf("unsupported Darwin runtime target darwin/%s", arch)
}

// DarwinPolicyDigest authenticates the exact Darwin output lock layered on
// the immutable observer source/patch lock.
func DarwinPolicyDigest() (string, error) {
	_, digest, err := embeddedDarwinPolicy()
	return digest, err
}

// DarwinTargetLock returns a copy of the exact selected Darwin output lock.
func DarwinTargetLock(arch string) (TargetLock, error) {
	target, _, err := selectDarwinTarget(arch)
	return target, err
}
