// Package windowssecurity defines and enforces the Windows security-descriptor
// contract used by Mesh secrets and installer-owned state.
package windowssecurity

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	LocalSystemSID    = "S-1-5-18"
	AdministratorsSID = "S-1-5-32-544"

	accessAllowedACEType = 0
	objectInheritACE     = 0x01
	containerInheritACE  = 0x02
	inheritedACE         = 0x10
	genericAll           = 0x10000000
	serviceAllAccess     = 0x000f01ff
)

type ObjectKind uint8

const (
	RegularFile ObjectKind = iota + 1
	Directory
)

type ACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   string
}

type Descriptor struct {
	OwnerSID      string
	DACLPresent   bool
	DACLNull      bool
	DACLDefaulted bool
	DACLProtected bool
	Entries       []ACE
}

// ValidatePrivateDescriptor requires the canonical Mesh DACL for one
// installer-owned object. The running service identity owns the object and is
// the only non-built-in principal with access; LocalSystem and the local
// Administrators group retain recovery authority.
func ValidatePrivateDescriptor(descriptor Descriptor, actorSID string, kind ObjectKind) error {
	return validatePrivateDescriptor(descriptor, actorSID, kind, false)
}

// ValidatePrivateChildDescriptor accepts the exact DACL inherited by a file
// created inside an already-authenticated protected Mesh directory. It does
// not accept explicit or mixed inherited authority and is intended only for
// dynamic lock, journal, and atomic-replacement files.
func ValidatePrivateChildDescriptor(descriptor Descriptor, actorSID string, kind ObjectKind) error {
	return validatePrivateDescriptor(descriptor, actorSID, kind, true)
}

func validatePrivateDescriptor(descriptor Descriptor, actorSID string, kind ObjectKind, inheritedChild bool) error {
	actorSID = strings.TrimSpace(actorSID)
	if !canonicalSID(actorSID) {
		return errors.New("Windows service identity SID is not canonical")
	}
	if kind != RegularFile && kind != Directory {
		return errors.New("Windows object kind is invalid")
	}
	if !descriptor.DACLPresent || descriptor.DACLNull {
		return errors.New("Windows object must have a non-null DACL")
	}
	if descriptor.DACLDefaulted {
		return errors.New("Windows object DACL must be explicit, not defaulted")
	}
	if !inheritedChild && !descriptor.DACLProtected {
		return errors.New("Windows object DACL must be protected from inheritance")
	}
	if inheritedChild && descriptor.DACLProtected {
		return errors.New("Windows dynamic child DACL must be inherited from its authenticated parent")
	}

	wantFlags := uint8(0)
	if kind == Directory {
		wantFlags = objectInheritACE | containerInheritACE
	}
	want := map[string]struct{}{
		actorSID:          {},
		LocalSystemSID:    {},
		AdministratorsSID: {},
	}
	if _, trustedOwner := want[descriptor.OwnerSID]; !trustedOwner {
		return fmt.Errorf("Windows object owner SID %q is not a trusted recovery principal", descriptor.OwnerSID)
	}
	seen := make(map[string]struct{}, len(want))
	for index, entry := range descriptor.Entries {
		if entry.Type != accessAllowedACEType {
			return fmt.Errorf("Windows DACL entry %d is not an access-allowed ACE", index)
		}
		if inheritedChild {
			if entry.Flags&inheritedACE == 0 || entry.Flags&^(inheritedACE|objectInheritACE|containerInheritACE) != 0 {
				return fmt.Errorf("Windows DACL entry %d has noncanonical inherited-child flags 0x%02x", index, entry.Flags)
			}
			if kind == Directory && entry.Flags != inheritedACE|objectInheritACE|containerInheritACE {
				return fmt.Errorf("Windows inherited directory DACL entry %d does not propagate authority to descendants", index)
			}
		} else if entry.Flags&inheritedACE != 0 || entry.Flags != wantFlags {
			return fmt.Errorf("Windows DACL entry %d has noncanonical inheritance flags 0x%02x", index, entry.Flags)
		}
		if entry.Mask != genericAll {
			return fmt.Errorf("Windows DACL entry %d has access mask 0x%08x, want GENERIC_ALL", index, entry.Mask)
		}
		if _, ok := want[entry.SID]; !ok {
			return fmt.Errorf("Windows DACL grants access to untrusted SID %q", entry.SID)
		}
		if _, duplicate := seen[entry.SID]; duplicate {
			return fmt.Errorf("Windows DACL repeats SID %q", entry.SID)
		}
		seen[entry.SID] = struct{}{}
	}
	if len(seen) != len(want) {
		missing := make([]string, 0, len(want)-len(seen))
		for sid := range want {
			if _, ok := seen[sid]; !ok {
				missing = append(missing, sid)
			}
		}
		sort.Strings(missing)
		return fmt.Errorf("Windows DACL is missing required full-control SID(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func canonicalSID(value string) bool {
	if len(value) < 7 || len(value) > 184 || !strings.HasPrefix(value, "S-1-") {
		return false
	}
	for _, part := range strings.Split(value[4:], "-") {
		if part == "" || len(part) > 20 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func ValidateActorSID(value string) error {
	if !canonicalSID(strings.TrimSpace(value)) {
		return errors.New("Windows service identity SID is not canonical")
	}
	return nil
}

// ValidatePrivateServiceDescriptor requires the service control object to be
// administered only by LocalSystem and the local Administrators group. The
// runtime service does not require a third trustee: it runs as LocalSystem,
// while Administrators retain explicit install and recovery authority.
func ValidatePrivateServiceDescriptor(descriptor Descriptor) error {
	if !descriptor.DACLPresent || descriptor.DACLNull {
		return errors.New("Windows service object must have a non-null DACL")
	}
	if descriptor.DACLDefaulted {
		return errors.New("Windows service object DACL must be explicit, not defaulted")
	}
	if !descriptor.DACLProtected {
		return errors.New("Windows service object DACL must be protected from inheritance")
	}
	if descriptor.OwnerSID != LocalSystemSID && descriptor.OwnerSID != AdministratorsSID {
		return fmt.Errorf("Windows service object owner SID %q is not a trusted recovery principal", descriptor.OwnerSID)
	}
	want := map[string]struct{}{LocalSystemSID: {}, AdministratorsSID: {}}
	seen := make(map[string]struct{}, len(want))
	for index, entry := range descriptor.Entries {
		if entry.Type != accessAllowedACEType {
			return fmt.Errorf("Windows service DACL entry %d is not an access-allowed ACE", index)
		}
		if entry.Flags != 0 {
			return fmt.Errorf("Windows service DACL entry %d has inheritance flags 0x%02x", index, entry.Flags)
		}
		if entry.Mask != serviceAllAccess {
			return fmt.Errorf("Windows service DACL entry %d has access mask 0x%08x, want SERVICE_ALL_ACCESS", index, entry.Mask)
		}
		if _, ok := want[entry.SID]; !ok {
			return fmt.Errorf("Windows service DACL grants access to untrusted SID %q", entry.SID)
		}
		if _, duplicate := seen[entry.SID]; duplicate {
			return fmt.Errorf("Windows service DACL repeats SID %q", entry.SID)
		}
		seen[entry.SID] = struct{}{}
	}
	if len(seen) != len(want) {
		return errors.New("Windows service DACL is missing LocalSystem or Administrators full control")
	}
	return nil
}
