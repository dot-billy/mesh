package nebulaobserverartifact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	observerassets "mesh/third_party/nebula-observer"
	windowsassets "mesh/third_party/nebula-windows-runtime"
)

const WindowsManifestSchema = "mesh.nebula-windows-runtime-stage.v1"

type windowsBuildPolicy struct {
	Schema                 string       `json:"schema"`
	BaseObserverLockSHA256 string       `json:"base_observer_lock_sha256"`
	Targets                []TargetLock `json:"targets"`
}

var (
	windowsOnce   sync.Once
	windowsPolicy windowsBuildPolicy
	windowsDigest string
	windowsErr    error
)

func embeddedWindowsPolicy() (windowsBuildPolicy, string, error) {
	windowsOnce.Do(func() {
		raw := windowsassets.BuildLock()
		windowsErr = decodeStrict(raw, &windowsPolicy)
		if windowsErr != nil {
			windowsErr = fmt.Errorf("invalid Windows runtime build lock: %w", windowsErr)
			return
		}
		canonical, err := json.MarshalIndent(windowsPolicy, "", "  ")
		if err != nil {
			windowsErr = fmt.Errorf("encode Windows runtime build lock: %w", err)
			return
		}
		canonical = append(canonical, '\n')
		if !bytes.Equal(raw, canonical) {
			windowsErr = errors.New("Windows runtime build lock is not canonically encoded")
			return
		}
		base := sha256.Sum256(observerassets.BuildLock())
		if windowsPolicy.Schema != "mesh.nebula-windows-runtime-build-lock.v1" ||
			windowsPolicy.BaseObserverLockSHA256 != hex.EncodeToString(base[:]) {
			windowsErr = errors.New("Windows runtime build lock does not bind the embedded observer source policy")
			return
		}
		if len(windowsPolicy.Targets) != 2 {
			windowsErr = errors.New("Windows runtime build lock must contain exactly two targets")
			return
		}
		for index, arch := range []string{"amd64", "arm64"} {
			target := windowsPolicy.Targets[index]
			if target.OS != "windows" || target.Arch != arch || len(target.Entries) != 2 {
				windowsErr = fmt.Errorf("Windows runtime target %d is not exact windows/%s policy", index, arch)
				return
			}
			for entryIndex, expected := range []struct{ name, main string }{
				{"nebula.exe", lockedModule + "/cmd/nebula"},
				{"nebula-cert.exe", lockedModule + "/cmd/nebula-cert"},
			} {
				entry := target.Entries[entryIndex]
				if entry.Name != expected.name || entry.MainPath != expected.main || entry.Mode != 0o555 ||
					entry.Size <= 0 || entry.Size > maximumBinarySize || !lowerHex(entry.SHA256) {
					windowsErr = fmt.Errorf("Windows runtime target %s entry %d is invalid", arch, entryIndex)
					return
				}
			}
		}
		digest := sha256.Sum256(raw)
		windowsDigest = hex.EncodeToString(digest[:])
	})
	clone := windowsPolicy
	clone.Targets = make([]TargetLock, len(windowsPolicy.Targets))
	for index, target := range windowsPolicy.Targets {
		clone.Targets[index] = cloneTarget(target)
	}
	return clone, windowsDigest, windowsErr
}

func selectWindowsTarget(arch string) (TargetLock, string, error) {
	policy, digest, err := embeddedWindowsPolicy()
	if err != nil {
		return TargetLock{}, "", err
	}
	for _, target := range policy.Targets {
		if target.Arch == arch {
			return cloneTarget(target), digest, nil
		}
	}
	return TargetLock{}, "", fmt.Errorf("unsupported Windows runtime target windows/%s", arch)
}

// WindowsPolicyDigest authenticates the exact Windows output lock layered on
// the immutable observer source/patch lock.
func WindowsPolicyDigest() (string, error) {
	_, digest, err := embeddedWindowsPolicy()
	return digest, err
}

// WindowsTargetLock returns a copy of the exact selected Windows output lock.
func WindowsTargetLock(arch string) (TargetLock, error) {
	target, _, err := selectWindowsTarget(arch)
	return target, err
}
