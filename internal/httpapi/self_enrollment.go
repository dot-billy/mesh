package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"mesh/internal/control"
	"mesh/internal/identity"
)

// selfEnrollmentRequest deliberately exposes no topology, address, route,
// lighthouse, or certificate-group authority. Those fields remain
// administrator-owned; a signed-in person may create only one ordinary mobile
// member enrollment with the fixed mobile policy below.
type selfEnrollmentRequest struct {
	Name string `json:"name"`
}

func (s *Server) createSelfEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		writeError(w, fmt.Errorf("%w: self enrollment does not accept query parameters", control.ErrInvalid))
		return
	}
	auth, ok := requestAuthentication(r.Context())
	if !ok {
		panic("self enrollment reached handler without request authentication")
	}
	// A browser-established OIDC session proves that the person authenticated
	// with their own identity. Legacy bearer, legacy browser, service, and
	// break-glass authorities must use the administrator enrollment route.
	if auth.session == nil || auth.principal.Kind != identity.PrincipalOIDCAdmin ||
		auth.session.AuthMethod != "oidc" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "OIDC user session required"})
		return
	}
	var input selfEnrollmentRequest
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, err)
		return
	}
	created, err := s.service.CreateNodeAs(
		auth.actor,
		r.PathValue("networkID"),
		control.CreateNodeInput{
			Name:   input.Name,
			Role:   "member",
			Site:   "mobile",
			Groups: []string{"members"},
		},
	)
	if errors.Is(err, control.ErrConflict) {
		reissued, reissueErr := s.service.ReissueSelfEnrollmentAs(
			auth.actor,
			r.PathValue("networkID"),
			input.Name,
		)
		if reissueErr == nil {
			created = control.CreatedNode{
				Node:            reissued.Node,
				EnrollmentToken: reissued.EnrollmentToken,
				ExpiresAt:       reissued.ExpiresAt,
			}
			err = nil
		}
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}
