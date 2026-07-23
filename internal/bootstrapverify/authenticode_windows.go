//go:build windows

package bootstrapverify

import "mesh/internal/windowsauthenticode"

func verifyPlatformAuthenticode(platformOS, installerPath string) (platformAuthenticodeVerification, error) {
	if platformOS != "windows" {
		return platformAuthenticodeVerification{}, nil
	}
	verified, err := windowsauthenticode.VerifyFile(installerPath, windowsauthenticode.MeshSignerRole)
	if err != nil {
		return platformAuthenticodeVerification{}, err
	}
	return platformAuthenticodeVerification{
		PolicySHA256: verified.PolicySHA256, SignerSPKISHA256: verified.SignerSPKISHA256,
		CertificateSHA256: verified.CertificateSHA256,
	}, nil
}
