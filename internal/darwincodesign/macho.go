package darwincodesign

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const (
	machOMagic64            = 0xfeedfacf
	loadCommandSegment64    = 0x19
	loadCommandCodeSig      = 0x1d
	codeSignatureSuperBlob  = 0xfade0cc0
	codeDirectoryMagic      = 0xfade0c02
	cmsBlobMagic            = 0xfade0b01
	entitlementsBlobMagic   = 0xfade7171
	derEntitlementsMagic    = 0xfade7172
	codeDirectorySlot       = 0
	entitlementsSlot        = 5
	derEntitlementsSlot     = 7
	cmsSignatureSlot        = 0x10000
	codeDirectoryAdHoc      = 0x2
	codeDirectoryRuntime    = 0x10000
	codeDirectoryLinkerSign = 0x20000
	maximumLoadCommands     = 64
	maximumLoadCommandBytes = 64 << 10
	maximumSignatureSize    = 4 << 20
)

type MachOSignatureEnvelope struct {
	Offset          int
	Size            int
	CodeFlags       uint32
	HasCMS          bool
	HasEntitlements bool
	HardenedRuntime bool
	AdHoc           bool
	LinkerSigned    bool
}

type machoSignatureLayout struct {
	envelope             MachOSignatureEnvelope
	linkeditVMSizeOffset int
	linkeditSizeOffset   int
	codeSigSizeOffset    int
	commandEnd           int
}

// InspectMachOSignature parses one thin little-endian 64-bit Mach-O and its
// bounded embedded signature container without making a trust decision.
func InspectMachOSignature(content []byte) (MachOSignatureEnvelope, error) {
	layout, err := parseMachOSignatureLayout(content)
	if err != nil {
		return MachOSignatureEnvelope{}, err
	}
	return layout.envelope, nil
}

// VerifySignedMachOReplacement proves that codesigning changed only the
// existing embedded signature plus the __LINKEDIT and LC_CODE_SIGNATURE size
// fields that necessarily describe it. This contract is intentionally limited
// to the thin linker-signed Go Mach-O shape used by the locked Mesh runtime.
func VerifySignedMachOReplacement(signed, linkerSigned []byte) (MachOSignatureEnvelope, error) {
	sourceLayout, err := parseMachOSignatureLayout(linkerSigned)
	if err != nil {
		return MachOSignatureEnvelope{}, fmt.Errorf("inspect linker-signed Darwin source: %w", err)
	}
	finalLayout, err := parseMachOSignatureLayout(signed)
	if err != nil {
		return MachOSignatureEnvelope{}, fmt.Errorf("inspect final signed Darwin executable: %w", err)
	}
	if !sourceLayout.envelope.AdHoc || !sourceLayout.envelope.LinkerSigned ||
		sourceLayout.envelope.HasCMS {
		return MachOSignatureEnvelope{}, errors.New("Darwin signing source is not one exact Go linker ad-hoc signature")
	}
	if finalLayout.envelope.AdHoc || finalLayout.envelope.LinkerSigned ||
		!finalLayout.envelope.HasCMS || !finalLayout.envelope.HardenedRuntime ||
		finalLayout.envelope.HasEntitlements {
		return MachOSignatureEnvelope{}, errors.New("final Darwin executable is not an entitlement-free CMS-backed hardened-runtime signature")
	}
	if sourceLayout.envelope.Offset != finalLayout.envelope.Offset ||
		sourceLayout.commandEnd != finalLayout.commandEnd ||
		sourceLayout.linkeditVMSizeOffset != finalLayout.linkeditVMSizeOffset ||
		sourceLayout.linkeditSizeOffset != finalLayout.linkeditSizeOffset ||
		sourceLayout.codeSigSizeOffset != finalLayout.codeSigSizeOffset {
		return MachOSignatureEnvelope{}, errors.New("Darwin codesigning changed the Mach-O load-command topology")
	}
	offset := sourceLayout.envelope.Offset
	sourcePrefix := append([]byte(nil), linkerSigned[:offset]...)
	finalPrefix := append([]byte(nil), signed[:offset]...)
	for _, mutable := range []struct {
		offset int
		size   int
	}{
		{sourceLayout.linkeditVMSizeOffset, 8},
		{sourceLayout.linkeditSizeOffset, 8},
		{sourceLayout.codeSigSizeOffset, 4},
	} {
		clear(sourcePrefix[mutable.offset : mutable.offset+mutable.size])
		clear(finalPrefix[mutable.offset : mutable.offset+mutable.size])
	}
	if !bytes.Equal(sourcePrefix, finalPrefix) {
		return MachOSignatureEnvelope{}, errors.New("Darwin codesigning changed bytes outside the exact signature size fields")
	}
	if bytes.Equal(
		linkerSigned[sourceLayout.envelope.Offset:],
		signed[finalLayout.envelope.Offset:],
	) {
		return MachOSignatureEnvelope{}, errors.New("Darwin final signature did not replace the linker signature")
	}
	return finalLayout.envelope, nil
}

func parseMachOSignatureLayout(content []byte) (machoSignatureLayout, error) {
	if len(content) < 32 || len(content) > 256<<20 ||
		binary.LittleEndian.Uint32(content[0:4]) != machOMagic64 {
		return machoSignatureLayout{}, errors.New("Darwin signed executable is not a bounded thin little-endian Mach-O 64 image")
	}
	commandCount := int(binary.LittleEndian.Uint32(content[16:20]))
	commandBytes := int(binary.LittleEndian.Uint32(content[20:24]))
	if commandCount < 1 || commandCount > maximumLoadCommands ||
		commandBytes < 8 || commandBytes > maximumLoadCommandBytes ||
		32+commandBytes > len(content) {
		return machoSignatureLayout{}, errors.New("Darwin Mach-O load-command table is outside its bound")
	}
	layout := machoSignatureLayout{commandEnd: 32 + commandBytes}
	offset := 32
	codeSignatureFound := false
	linkeditFound := false
	var linkeditFileOffset, linkeditFileSize uint64
	for index := 0; index < commandCount; index++ {
		if offset+8 > layout.commandEnd {
			return machoSignatureLayout{}, errors.New("Darwin Mach-O load command is truncated")
		}
		command := binary.LittleEndian.Uint32(content[offset : offset+4])
		size := int(binary.LittleEndian.Uint32(content[offset+4 : offset+8]))
		if size < 8 || size%8 != 0 || offset+size > layout.commandEnd {
			return machoSignatureLayout{}, errors.New("Darwin Mach-O load command size is invalid")
		}
		switch command {
		case loadCommandSegment64:
			if size < 72 {
				return machoSignatureLayout{}, errors.New("Darwin Mach-O segment command is truncated")
			}
			name := string(bytes.TrimRight(content[offset+8:offset+24], "\x00"))
			if name == "__LINKEDIT" {
				if linkeditFound {
					return machoSignatureLayout{}, errors.New("Darwin Mach-O repeats __LINKEDIT")
				}
				linkeditFound = true
				layout.linkeditVMSizeOffset = offset + 32
				layout.linkeditSizeOffset = offset + 48
				linkeditFileOffset = binary.LittleEndian.Uint64(content[offset+40 : offset+48])
				linkeditFileSize = binary.LittleEndian.Uint64(content[offset+48 : offset+56])
			}
		case loadCommandCodeSig:
			if codeSignatureFound || size != 16 || index != commandCount-1 {
				return machoSignatureLayout{}, errors.New("Darwin Mach-O code-signature command is repeated, malformed, or not final")
			}
			codeSignatureFound = true
			layout.envelope.Offset = int(binary.LittleEndian.Uint32(content[offset+8 : offset+12]))
			layout.envelope.Size = int(binary.LittleEndian.Uint32(content[offset+12 : offset+16]))
			layout.codeSigSizeOffset = offset + 12
		}
		offset += size
	}
	if offset != layout.commandEnd || !linkeditFound || !codeSignatureFound {
		return machoSignatureLayout{}, errors.New("Darwin Mach-O lacks one exact __LINKEDIT or code-signature command")
	}
	envelope := &layout.envelope
	if envelope.Offset < layout.commandEnd || envelope.Offset%16 != 0 ||
		envelope.Size < 64 || envelope.Size > maximumSignatureSize ||
		envelope.Offset > len(content)-envelope.Size ||
		envelope.Offset+envelope.Size != len(content) ||
		linkeditFileOffset > uint64(envelope.Offset) ||
		linkeditFileOffset+linkeditFileSize != uint64(len(content)) {
		return machoSignatureLayout{}, errors.New("Darwin Mach-O embedded signature is outside the exact __LINKEDIT bound")
	}
	flags, cms, entitlements, err := inspectSignatureSuperBlob(content[envelope.Offset:])
	if err != nil {
		return machoSignatureLayout{}, err
	}
	envelope.CodeFlags = flags
	envelope.HasCMS = cms
	envelope.HasEntitlements = entitlements
	envelope.HardenedRuntime = flags&codeDirectoryRuntime != 0
	envelope.AdHoc = flags&codeDirectoryAdHoc != 0
	envelope.LinkerSigned = flags&codeDirectoryLinkerSign != 0
	return layout, nil
}

func inspectSignatureSuperBlob(raw []byte) (flags uint32, hasCMS, hasEntitlements bool, returnErr error) {
	if len(raw) < 20 || binary.BigEndian.Uint32(raw[0:4]) != codeSignatureSuperBlob ||
		int(binary.BigEndian.Uint32(raw[4:8])) != len(raw) {
		return 0, false, false, errors.New("Darwin code signature is not one exact embedded SuperBlob")
	}
	count := int(binary.BigEndian.Uint32(raw[8:12]))
	if count < 1 || count > 64 || 12+count*8 > len(raw) {
		return 0, false, false, errors.New("Darwin code-signature slot index is outside its bound")
	}
	type indexedBlob struct {
		slot   uint32
		offset int
	}
	blobs := make([]indexedBlob, count)
	seenSlots := make(map[uint32]struct{}, count)
	for index := 0; index < count; index++ {
		base := 12 + index*8
		blob := indexedBlob{
			slot:   binary.BigEndian.Uint32(raw[base : base+4]),
			offset: int(binary.BigEndian.Uint32(raw[base+4 : base+8])),
		}
		if blob.offset < 12+count*8 || blob.offset > len(raw)-8 {
			return 0, false, false, errors.New("Darwin code-signature blob offset is invalid")
		}
		if _, duplicate := seenSlots[blob.slot]; duplicate {
			return 0, false, false, errors.New("Darwin code-signature slot is duplicated")
		}
		seenSlots[blob.slot] = struct{}{}
		blobs[index] = blob
	}
	sort.Slice(blobs, func(left, right int) bool { return blobs[left].offset < blobs[right].offset })
	codeDirectoryFound := false
	for index, blob := range blobs {
		magic := binary.BigEndian.Uint32(raw[blob.offset : blob.offset+4])
		length := int(binary.BigEndian.Uint32(raw[blob.offset+4 : blob.offset+8]))
		end := blob.offset + length
		next := len(raw)
		if index+1 < len(blobs) {
			next = blobs[index+1].offset
		}
		if length < 8 || end > next {
			return 0, false, false, errors.New("Darwin code-signature indexed blob length is invalid")
		}
		switch blob.slot {
		case codeDirectorySlot:
			if magic != codeDirectoryMagic || length < 16 {
				return 0, false, false, errors.New("Darwin primary CodeDirectory is invalid")
			}
			flags = binary.BigEndian.Uint32(raw[blob.offset+12 : blob.offset+16])
			codeDirectoryFound = true
		case cmsSignatureSlot:
			if magic != cmsBlobMagic || length < 9 {
				return 0, false, false, errors.New("Darwin CMS signature blob is invalid")
			}
			hasCMS = true
		case entitlementsSlot:
			if magic != entitlementsBlobMagic {
				return 0, false, false, errors.New("Darwin XML entitlement blob is invalid")
			}
			hasEntitlements = true
		case derEntitlementsSlot:
			if magic != derEntitlementsMagic {
				return 0, false, false, errors.New("Darwin DER entitlement blob is invalid")
			}
			hasEntitlements = true
		}
	}
	if !codeDirectoryFound {
		return 0, false, false, errors.New("Darwin code signature has no primary CodeDirectory")
	}
	return flags, hasCMS, hasEntitlements, nil
}
