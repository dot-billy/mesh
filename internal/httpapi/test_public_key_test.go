package httpapi

import (
	"bytes"

	nebulacert "github.com/slackhq/nebula/cert"
)

func testNebulaPublicKey(fill byte) string {
	return string(nebulacert.MarshalPublicKeyToPEM(nebulacert.Curve_CURVE25519, bytes.Repeat([]byte{fill}, 32)))
}
