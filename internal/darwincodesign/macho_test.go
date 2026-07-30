package darwincodesign

import (
	"encoding/binary"
	"testing"
)

func TestSignedMachOReplacementAllowsOnlySignatureShape(t *testing.T) {
	source := syntheticMachO(t, codeDirectoryAdHoc|codeDirectoryLinkerSign, false, 96)
	signed := syntheticMachO(t, codeDirectoryRuntime, true, 128)
	envelope, err := VerifySignedMachOReplacement(signed, source)
	if err != nil {
		t.Fatal(err)
	}
	if !envelope.HasCMS || !envelope.HardenedRuntime || envelope.AdHoc || envelope.LinkerSigned {
		t.Fatalf("unexpected final envelope: %+v", envelope)
	}
	mutated := append([]byte(nil), signed...)
	mutated[124] ^= 1
	if _, err := VerifySignedMachOReplacement(mutated, source); err == nil {
		t.Fatal("Mach-O code-region mutation was accepted")
	}
}

func TestSignedMachOReplacementRejectsAdHocOrMalformedFinal(t *testing.T) {
	source := syntheticMachO(t, codeDirectoryAdHoc|codeDirectoryLinkerSign, false, 96)
	for name, final := range map[string][]byte{
		"ad hoc":      syntheticMachO(t, codeDirectoryAdHoc, false, 96),
		"no runtime":  syntheticMachO(t, 0, true, 128),
		"entitlement": syntheticMachOWithEntitlements(t, codeDirectoryRuntime, true, true, 144),
		"truncated":   syntheticMachO(t, codeDirectoryRuntime, true, 128)[:200],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifySignedMachOReplacement(final, source); err == nil {
				t.Fatal("invalid signed Mach-O replacement accepted")
			}
		})
	}
}

func syntheticMachO(t *testing.T, flags uint32, cms bool, signatureSize int) []byte {
	return syntheticMachOWithEntitlements(t, flags, cms, false, signatureSize)
}

func syntheticMachOWithEntitlements(t *testing.T, flags uint32, cms, entitlements bool, signatureSize int) []byte {
	t.Helper()
	const signatureOffset = 128
	indexCount := 1
	if cms {
		indexCount++
	}
	if entitlements {
		indexCount++
	}
	minimum := 12 + indexCount*8 + 16
	if cms {
		minimum += 9
	}
	if entitlements {
		minimum += 8
	}
	if signatureSize < minimum {
		t.Fatal("synthetic signature size is too small")
	}
	content := make([]byte, signatureOffset+signatureSize)
	little := binary.LittleEndian
	little.PutUint32(content[0:4], machOMagic64)
	little.PutUint32(content[16:20], 2)
	little.PutUint32(content[20:24], 88)
	segment := 32
	little.PutUint32(content[segment:segment+4], loadCommandSegment64)
	little.PutUint32(content[segment+4:segment+8], 72)
	copy(content[segment+8:segment+24], "__LINKEDIT")
	little.PutUint64(content[segment+32:segment+40], uint64(signatureSize))
	little.PutUint64(content[segment+40:segment+48], signatureOffset)
	little.PutUint64(content[segment+48:segment+56], uint64(signatureSize))
	code := segment + 72
	little.PutUint32(content[code:code+4], loadCommandCodeSig)
	little.PutUint32(content[code+4:code+8], 16)
	little.PutUint32(content[code+8:code+12], signatureOffset)
	little.PutUint32(content[code+12:code+16], uint32(signatureSize))
	for index := 120; index < signatureOffset; index++ {
		content[index] = byte(index)
	}
	raw := content[signatureOffset:]
	big := binary.BigEndian
	big.PutUint32(raw[0:4], codeSignatureSuperBlob)
	big.PutUint32(raw[4:8], uint32(len(raw)))
	big.PutUint32(raw[8:12], uint32(indexCount))
	codeOffset := 12 + indexCount*8
	big.PutUint32(raw[12:16], codeDirectorySlot)
	big.PutUint32(raw[16:20], uint32(codeOffset))
	codeLength := len(raw) - codeOffset
	if cms {
		codeLength -= 9
	}
	if entitlements {
		codeLength -= 8
	}
	big.PutUint32(raw[codeOffset:codeOffset+4], codeDirectoryMagic)
	big.PutUint32(raw[codeOffset+4:codeOffset+8], uint32(codeLength))
	big.PutUint32(raw[codeOffset+12:codeOffset+16], flags)
	index := 1
	nextOffset := codeOffset + codeLength
	if cms {
		base := 12 + index*8
		big.PutUint32(raw[base:base+4], cmsSignatureSlot)
		big.PutUint32(raw[base+4:base+8], uint32(nextOffset))
		big.PutUint32(raw[nextOffset:nextOffset+4], cmsBlobMagic)
		big.PutUint32(raw[nextOffset+4:nextOffset+8], 9)
		raw[nextOffset+8] = 1
		nextOffset += 9
		index++
	}
	if entitlements {
		base := 12 + index*8
		big.PutUint32(raw[base:base+4], entitlementsSlot)
		big.PutUint32(raw[base+4:base+8], uint32(nextOffset))
		big.PutUint32(raw[nextOffset:nextOffset+4], entitlementsBlobMagic)
		big.PutUint32(raw[nextOffset+4:nextOffset+8], 8)
	}
	return content
}
