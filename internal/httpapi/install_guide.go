package httpapi

import "net/http"

const installGuideSchema = "mesh-install-guide-v2"

type installGuideResponse struct {
	Schema string            `json:"schema"`
	Linux  linuxInstallGuide `json:"linux"`
}

type linuxInstallGuide struct {
	OnlineAvailable     bool   `json:"online_available"`
	BundleURL           string `json:"bundle_url,omitempty"`
	BootstrapHandoffURL string `json:"bootstrap_handoff_url,omitempty"`
}

func (s *Server) installGuide(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, installGuideResponse{
		Schema: installGuideSchema,
		Linux: linuxInstallGuide{
			OnlineAvailable:     s.linuxInstallBundleURL != "",
			BundleURL:           s.linuxInstallBundleURL,
			BootstrapHandoffURL: s.linuxBootstrapHandoffURL,
		},
	})
}
