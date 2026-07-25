package windowssecurity

import (
	"strings"
	"testing"
)

const testActorSID = "S-1-5-21-111-222-333-1001"

func canonicalDescriptor(kind ObjectKind) Descriptor {
	flags := uint8(0)
	if kind == Directory {
		flags = objectInheritACE | containerInheritACE
	}
	return Descriptor{
		OwnerSID: testActorSID, DACLPresent: true, DACLProtected: true,
		Entries: []ACE{
			{Type: accessAllowedACEType, Flags: flags, Mask: genericAll, SID: testActorSID},
			{Type: accessAllowedACEType, Flags: flags, Mask: genericAll, SID: LocalSystemSID},
			{Type: accessAllowedACEType, Flags: flags, Mask: genericAll, SID: AdministratorsSID},
		},
	}
}

func TestValidatePrivateDescriptorAcceptsCanonicalFileAndDirectory(t *testing.T) {
	for _, kind := range []ObjectKind{RegularFile, Directory} {
		if err := ValidatePrivateDescriptor(canonicalDescriptor(kind), testActorSID, kind); err != nil {
			t.Fatalf("kind %d: %v", kind, err)
		}
	}
}

func TestValidatePrivateChildDescriptorAcceptsExactInheritedAuthority(t *testing.T) {
	value := canonicalDescriptor(RegularFile)
	value.DACLProtected = false
	for index := range value.Entries {
		value.Entries[index].Flags = inheritedACE
	}
	if err := ValidatePrivateChildDescriptor(value, testActorSID, RegularFile); err != nil {
		t.Fatal(err)
	}
	value.Entries[0].Flags = 0
	if err := ValidatePrivateChildDescriptor(value, testActorSID, RegularFile); err == nil || !strings.Contains(err.Error(), "inherited-child") {
		t.Fatalf("explicit child ACE error = %v", err)
	}
	value.Entries[0].Flags = inheritedACE
	value.DACLProtected = true
	if err := ValidatePrivateChildDescriptor(value, testActorSID, RegularFile); err == nil || !strings.Contains(err.Error(), "must be inherited") {
		t.Fatalf("protected child error = %v", err)
	}
}

func TestValidatePrivateChildDirectoryRequiresPropagatingAuthority(t *testing.T) {
	value := canonicalDescriptor(Directory)
	value.DACLProtected = false
	for index := range value.Entries {
		value.Entries[index].Flags |= inheritedACE
	}
	if err := ValidatePrivateChildDescriptor(value, testActorSID, Directory); err != nil {
		t.Fatal(err)
	}
	value.Entries[0].Flags = inheritedACE | containerInheritACE
	if err := ValidatePrivateChildDescriptor(value, testActorSID, Directory); err == nil || !strings.Contains(err.Error(), "propagate authority") {
		t.Fatalf("nonpropagating directory error = %v", err)
	}
}

func TestValidatePrivateDescriptorRejectsAuthorityDrift(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Descriptor)
		want string
	}{
		{name: "owner", edit: func(value *Descriptor) { value.OwnerSID = "S-1-1-0" }, want: "owner"},
		{name: "absent DACL", edit: func(value *Descriptor) { value.DACLPresent = false }, want: "non-null"},
		{name: "null DACL", edit: func(value *Descriptor) { value.DACLNull = true }, want: "non-null"},
		{name: "defaulted", edit: func(value *Descriptor) { value.DACLDefaulted = true }, want: "explicit"},
		{name: "unprotected", edit: func(value *Descriptor) { value.DACLProtected = false }, want: "protected"},
		{name: "deny ACE", edit: func(value *Descriptor) { value.Entries[0].Type = 1 }, want: "access-allowed"},
		{name: "inherited ACE", edit: func(value *Descriptor) { value.Entries[0].Flags |= inheritedACE }, want: "inheritance flags"},
		{name: "wrong mask", edit: func(value *Descriptor) { value.Entries[0].Mask = 0x80000000 }, want: "GENERIC_ALL"},
		{name: "broad trustee", edit: func(value *Descriptor) { value.Entries[0].SID = "S-1-1-0" }, want: "untrusted SID"},
		{name: "duplicate", edit: func(value *Descriptor) { value.Entries[0].SID = LocalSystemSID }, want: "repeats SID"},
		{name: "missing", edit: func(value *Descriptor) { value.Entries = value.Entries[:2] }, want: "missing required"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := canonicalDescriptor(RegularFile)
			test.edit(&value)
			err := ValidatePrivateDescriptor(value, testActorSID, RegularFile)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidatePrivateDescriptorRejectsKindAndSIDDrift(t *testing.T) {
	if err := ValidatePrivateDescriptor(canonicalDescriptor(RegularFile), "S-1-5-021", RegularFile); err == nil {
		t.Fatal("noncanonical actor SID accepted")
	}
	if err := ValidatePrivateDescriptor(canonicalDescriptor(RegularFile), testActorSID, ObjectKind(99)); err == nil {
		t.Fatal("unknown object kind accepted")
	}
	if err := ValidatePrivateDescriptor(canonicalDescriptor(Directory), testActorSID, RegularFile); err == nil {
		t.Fatal("directory inheritance flags accepted for a file")
	}
}

func canonicalServiceDescriptor() Descriptor {
	return Descriptor{
		OwnerSID: AdministratorsSID, DACLPresent: true, DACLProtected: true,
		Entries: []ACE{
			{Type: accessAllowedACEType, Mask: serviceAllAccess, SID: LocalSystemSID},
			{Type: accessAllowedACEType, Mask: serviceAllAccess, SID: AdministratorsSID},
		},
	}
}

func TestValidatePrivateServiceDescriptor(t *testing.T) {
	if err := ValidatePrivateServiceDescriptor(canonicalServiceDescriptor()); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*Descriptor)
		want string
	}{
		{name: "owner", edit: func(value *Descriptor) { value.OwnerSID = "S-1-1-0" }, want: "owner"},
		{name: "unprotected", edit: func(value *Descriptor) { value.DACLProtected = false }, want: "protected"},
		{name: "broad trustee", edit: func(value *Descriptor) { value.Entries[0].SID = "S-1-1-0" }, want: "untrusted"},
		{name: "wrong access", edit: func(value *Descriptor) { value.Entries[0].Mask = genericAll }, want: "SERVICE_ALL_ACCESS"},
		{name: "inherited", edit: func(value *Descriptor) { value.Entries[0].Flags = inheritedACE }, want: "inheritance"},
		{name: "missing", edit: func(value *Descriptor) { value.Entries = value.Entries[:1] }, want: "missing"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := canonicalServiceDescriptor()
			test.edit(&value)
			err := ValidatePrivateServiceDescriptor(value)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}
