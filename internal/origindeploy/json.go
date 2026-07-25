package origindeploy

import releasetrust "mesh/internal/release"

func validateStrictJSON(raw []byte) error {
	return releasetrust.ValidateStrictJSON(raw)
}
