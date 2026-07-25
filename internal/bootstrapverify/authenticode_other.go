//go:build !windows

package bootstrapverify

func verifyPlatformAuthenticode(string, string) (platformAuthenticodeVerification, error) {
	return platformAuthenticodeVerification{}, nil
}
