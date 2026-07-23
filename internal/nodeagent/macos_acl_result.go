package nodeagent

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// These values are the stable Darwin sys/attr.h and sys/kauth.h wire
// constants used by fgetattrlist. Both supported Darwin architectures are
// little-endian and return the same packed representation.
const (
	darwinAttrCommonExtendedSecurity = uint32(0x00400000)
	darwinAttrCommonReturnedAttrs    = uint32(0x80000000)
	darwinFileSecMagic               = uint32(0x012cc16d)
	darwinFileSecNoACL               = ^uint32(0)
	darwinACLResultFixedBytes        = 32 // length + attribute_set_t + attrreference
	darwinFileSecHeaderBytes         = 44 // magic + two GUIDs + kauth_acl header
	darwinACEBytes                   = 24
	darwinMaxACLEntries              = 128
)

// parseDarwinExtendedSecurityResult validates the exact result of a Darwin
// fgetattrlist request for ATTR_CMN_RETURNED_ATTRS and
// ATTR_CMN_EXTENDED_SECURITY with FSOPT_PACK_INVAL_ATTRS. It distinguishes the
// kernel's explicit KAUTH_FILESEC_NOACL sentinel from an empty or populated
// ACL; both of the latter are access-control objects and therefore rejected by
// callers.
func parseDarwinExtendedSecurityResult(raw []byte) (hasACL bool, err error) {
	if len(raw) < darwinACLResultFixedBytes {
		return false, errors.New("Darwin extended-security result is truncated")
	}
	declared := binary.LittleEndian.Uint32(raw[0:4])
	if uint64(declared) != uint64(len(raw)) {
		return false, fmt.Errorf("Darwin extended-security result length is %d, got %d bytes", declared, len(raw))
	}
	common := binary.LittleEndian.Uint32(raw[4:8])
	const allowed = darwinAttrCommonReturnedAttrs | darwinAttrCommonExtendedSecurity
	if common&darwinAttrCommonReturnedAttrs == 0 || common & ^uint32(allowed) != 0 {
		return false, errors.New("Darwin extended-security result has an invalid returned-attribute set")
	}
	for offset := 8; offset < 24; offset += 4 {
		if binary.LittleEndian.Uint32(raw[offset:offset+4]) != 0 {
			return false, errors.New("Darwin extended-security result has an unexpected non-common attribute")
		}
	}

	dataOffset := int32(binary.LittleEndian.Uint32(raw[24:28]))
	dataLength := binary.LittleEndian.Uint32(raw[28:32])
	if dataOffset != 8 {
		return false, fmt.Errorf("Darwin extended-security attribute offset is %d, want 8", dataOffset)
	}
	paddedLength := (uint64(dataLength) + 3) &^ 3
	wantLength := uint64(darwinACLResultFixedBytes) + paddedLength
	if wantLength != uint64(len(raw)) {
		return false, errors.New("Darwin extended-security attribute length is inconsistent with its result")
	}
	for _, value := range raw[darwinACLResultFixedBytes+int(dataLength):] {
		if value != 0 {
			return false, errors.New("Darwin extended-security result has nonzero alignment padding")
		}
	}

	attributeReturned := common&darwinAttrCommonExtendedSecurity != 0
	if dataLength == 0 {
		if attributeReturned {
			return false, errors.New("Darwin reported extended security without an ACL representation")
		}
		return false, nil
	}
	if !attributeReturned {
		return false, errors.New("Darwin returned an ACL representation without marking the attribute valid")
	}
	blob := raw[darwinACLResultFixedBytes : darwinACLResultFixedBytes+int(dataLength)]
	if len(blob) < darwinFileSecHeaderBytes {
		return false, errors.New("Darwin extended-security ACL representation is truncated")
	}
	if binary.LittleEndian.Uint32(blob[0:4]) != darwinFileSecMagic {
		return false, errors.New("Darwin extended-security ACL representation has invalid magic")
	}
	for _, value := range blob[4:36] {
		if value != 0 {
			return false, errors.New("Darwin extended-security ACL representation has unexpected owner or group GUIDs")
		}
	}
	entryCount := binary.LittleEndian.Uint32(blob[36:40])
	if entryCount == darwinFileSecNoACL {
		if len(blob) != darwinFileSecHeaderBytes {
			return false, errors.New("Darwin no-ACL sentinel has trailing access-control entries")
		}
		return false, nil
	}
	if entryCount > darwinMaxACLEntries {
		return false, errors.New("Darwin extended-security ACL entry count exceeds the kernel limit")
	}
	wantBlobLength := uint64(darwinFileSecHeaderBytes) + uint64(entryCount)*darwinACEBytes
	if wantBlobLength != uint64(len(blob)) {
		return false, errors.New("Darwin extended-security ACL entry count does not match its representation")
	}
	return true, nil
}
