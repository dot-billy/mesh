package nodeagent

import (
	"encoding/binary"
	"strings"
	"testing"
)

func darwinACLResult(t *testing.T, returned bool, blob []byte) []byte {
	t.Helper()
	padded := (len(blob) + 3) &^ 3
	raw := make([]byte, darwinACLResultFixedBytes+padded)
	binary.LittleEndian.PutUint32(raw[0:4], uint32(len(raw)))
	common := darwinAttrCommonReturnedAttrs
	if returned {
		common |= darwinAttrCommonExtendedSecurity
	}
	binary.LittleEndian.PutUint32(raw[4:8], common)
	binary.LittleEndian.PutUint32(raw[24:28], 8)
	binary.LittleEndian.PutUint32(raw[28:32], uint32(len(blob)))
	copy(raw[darwinACLResultFixedBytes:], blob)
	return raw
}

func darwinFileSecBlob(entryCount uint32) []byte {
	entries := uint64(entryCount)
	if entryCount == darwinFileSecNoACL {
		entries = 0
	}
	blob := make([]byte, uint64(darwinFileSecHeaderBytes)+entries*darwinACEBytes)
	binary.LittleEndian.PutUint32(blob[0:4], darwinFileSecMagic)
	binary.LittleEndian.PutUint32(blob[36:40], entryCount)
	return blob
}

func TestParseDarwinExtendedSecurityResultAcceptsOnlyNoACL(t *testing.T) {
	for _, test := range []struct {
		name   string
		raw    []byte
		hasACL bool
	}{
		{name: "unsupported-or-null", raw: darwinACLResult(t, false, nil)},
		{name: "kernel-no-acl-sentinel", raw: darwinACLResult(t, true, darwinFileSecBlob(darwinFileSecNoACL))},
		{name: "empty-acl-object", raw: darwinACLResult(t, true, darwinFileSecBlob(0)), hasACL: true},
		{name: "one-entry-acl", raw: darwinACLResult(t, true, darwinFileSecBlob(1)), hasACL: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			hasACL, err := parseDarwinExtendedSecurityResult(test.raw)
			if err != nil || hasACL != test.hasACL {
				t.Fatalf("parse result: hasACL=%v err=%v, want hasACL=%v", hasACL, err, test.hasACL)
			}
		})
	}
}

func TestParseDarwinExtendedSecurityResultRejectsMalformedKernelData(t *testing.T) {
	validAbsent := darwinACLResult(t, false, nil)
	validNoACL := darwinACLResult(t, true, darwinFileSecBlob(darwinFileSecNoACL))
	mutate := func(raw []byte, change func([]byte)) []byte {
		clone := append([]byte(nil), raw...)
		change(clone)
		return clone
	}
	for _, test := range []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "truncated", raw: validAbsent[:31], want: "truncated"},
		{name: "declared-size", raw: mutate(validAbsent, func(raw []byte) { binary.LittleEndian.PutUint32(raw[0:4], 31) }), want: "length"},
		{name: "missing-returned-set", raw: mutate(validAbsent, func(raw []byte) { binary.LittleEndian.PutUint32(raw[4:8], 0) }), want: "returned-attribute"},
		{name: "foreign-common-bit", raw: mutate(validAbsent, func(raw []byte) { binary.LittleEndian.PutUint32(raw[4:8], darwinAttrCommonReturnedAttrs|1) }), want: "returned-attribute"},
		{name: "foreign-group", raw: mutate(validAbsent, func(raw []byte) { binary.LittleEndian.PutUint32(raw[8:12], 1) }), want: "non-common"},
		{name: "bad-offset", raw: mutate(validAbsent, func(raw []byte) { binary.LittleEndian.PutUint32(raw[24:28], 4) }), want: "offset"},
		{name: "valid-bit-without-blob", raw: mutate(validAbsent, func(raw []byte) {
			binary.LittleEndian.PutUint32(raw[4:8], darwinAttrCommonReturnedAttrs|darwinAttrCommonExtendedSecurity)
		}), want: "without an ACL"},
		{name: "blob-without-valid-bit", raw: darwinACLResult(t, false, darwinFileSecBlob(darwinFileSecNoACL)), want: "without marking"},
		{name: "bad-magic", raw: mutate(validNoACL, func(raw []byte) { raw[32] ^= 1 }), want: "magic"},
		{name: "non-null-guid", raw: mutate(validNoACL, func(raw []byte) { raw[36] = 1 }), want: "GUID"},
		{name: "no-acl-trailing-entry", raw: darwinACLResult(t, true, append(darwinFileSecBlob(darwinFileSecNoACL), make([]byte, darwinACEBytes)...)), want: "trailing"},
		{name: "too-many-entries", raw: mutate(validNoACL, func(raw []byte) { binary.LittleEndian.PutUint32(raw[68:72], darwinMaxACLEntries+1) }), want: "kernel limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseDarwinExtendedSecurityResult(test.raw)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parse error = %v, want text %q", err, test.want)
			}
		})
	}
}
