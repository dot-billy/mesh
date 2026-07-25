package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"mesh/internal/control"
	"mesh/internal/identity"
)

const (
	desktopAuthorizationLifetime     = 5 * time.Minute
	desktopAuthorizationPollInterval = 5 * time.Second
)

type desktopAuthorizationStartResponse struct {
	RequestID       string    `json:"request_id"`
	PollSecret      string    `json:"poll_secret"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	IntervalSeconds int64     `json:"interval_seconds"`
}

type desktopAuthorizationCompleteRequest struct {
	RequestID  string
	PollSecret string
}

type desktopAuthorizationCompletionResponse struct {
	State           string           `json:"state"`
	ExpiresAt       time.Time        `json:"expires_at"`
	IntervalSeconds int64            `json:"interval_seconds"`
	Session         *sessionResponse `json:"session,omitempty"`
}

func (s *Server) desktopAuthorizationStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || !s.validSameOriginJSON(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "desktop authorization request was rejected"})
		return
	}
	if err := decodeDesktopAuthorizationStart(r); err != nil {
		writeError(w, err)
		return
	}
	idToken, err := identity.NewOpaqueToken()
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	pollSecret, err := identity.NewOpaqueToken()
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	now := s.currentTime()
	expiresAt := now.Add(desktopAuthorizationLifetime)
	requestID := "desktop_" + idToken
	if err := s.sessions.CreateDesktopAuthorization(r.Context(), identity.CreateDesktopAuthorizationInput{
		ID: requestID, PollSecret: pollSecret, CreatedAt: now, ExpiresAt: expiresAt,
		PollInterval: desktopAuthorizationPollInterval,
	}); err != nil {
		writeIdentityError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, desktopAuthorizationStartResponse{
		RequestID: requestID, PollSecret: pollSecret,
		VerificationURL: s.desktopVerificationURL(requestID), ExpiresAt: expiresAt,
		IntervalSeconds: int64(desktopAuthorizationPollInterval / time.Second),
	})
}

func (s *Server) desktopAuthorizationDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	auth, ok := requestAuthentication(r.Context())
	if !ok {
		panic("desktop authorization decision reached handler without request authentication")
	}
	if auth.session == nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "browser session required"})
		return
	}
	if r.URL.RawQuery != "" || !s.validSameOriginJSON(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "desktop authorization decision was rejected"})
		return
	}
	requestID := r.PathValue("requestID")
	if !identity.ValidDesktopAuthorizationRequestID(requestID) {
		writeError(w, fmt.Errorf("%w: desktop authorization request ID is invalid", control.ErrInvalid))
		return
	}
	decision, err := decodeDesktopAuthorizationDecision(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if err := s.sessions.DecideDesktopAuthorization(r.Context(), requestID, auth.principal, identity.DesktopAuthorizationDecision(decision), s.currentTime()); err != nil {
		writeIdentityError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) desktopAuthorizationComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || !s.validSameOriginJSON(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "desktop authorization completion was rejected"})
		return
	}
	input, err := decodeDesktopAuthorizationComplete(r)
	if err != nil {
		writeError(w, err)
		return
	}
	poll, err := s.sessions.PollDesktopAuthorization(r.Context(), input.RequestID, input.PollSecret, s.currentTime())
	if err != nil {
		if errors.Is(err, identity.ErrLimit) {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(desktopAuthorizationPollInterval/time.Second), 10))
		}
		writeIdentityError(w, err)
		return
	}
	response := desktopAuthorizationCompletionResponse{
		State: string(poll.State), ExpiresAt: poll.ExpiresAt,
		IntervalSeconds: int64(poll.PollInterval / time.Second),
	}
	if poll.State != identity.DesktopAuthorizationApproved {
		writeJSON(w, http.StatusOK, response)
		return
	}
	role, permissions, err := s.accessForPrincipal(poll.Principal)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	now := s.currentTime()
	session, sessionToken, csrfToken, err := s.createSession(r.Context(), poll.Principal, now)
	if err != nil {
		writeIdentityError(w, err)
		return
	}
	s.setSessionCookies(w, sessionToken, csrfToken, session.AbsoluteExpiresAt, now)
	current := sessionResponseForAccess(session, role, permissions)
	response.State = "authorized"
	response.Session = &current
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) desktopVerificationURL(requestID string) string {
	parsed, err := url.Parse(s.identityConfig.PublicURL)
	if err != nil {
		panic("normalized public URL could not be parsed")
	}
	parsed.Path = "/"
	parsed.RawPath = ""
	query := parsed.Query()
	query.Set("mesh_desktop_request", requestID)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func decodeDesktopAuthorizationStart(r *http.Request) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1024)
	decoder := json.NewDecoder(r.Body)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') || decoder.More() {
		return fmt.Errorf("%w: desktop authorization start requires one empty JSON object", control.ErrInvalid)
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return fmt.Errorf("%w: desktop authorization start requires one empty JSON object", control.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: desktop authorization start requires one empty JSON object", control.ErrInvalid)
	}
	return nil
}

func decodeDesktopAuthorizationDecision(r *http.Request) (string, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 1024)
	decoder := json.NewDecoder(r.Body)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return "", fmt.Errorf("%w: malformed desktop authorization decision", control.ErrInvalid)
	}
	decision := ""
	seen := false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil || key != "decision" || seen {
			return "", fmt.Errorf("%w: desktop authorization decision must contain exactly one decision", control.ErrInvalid)
		}
		if err := decoder.Decode(&decision); err != nil {
			return "", fmt.Errorf("%w: malformed desktop authorization decision", control.ErrInvalid)
		}
		seen = true
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seen ||
		(decision != string(identity.DesktopAuthorizationApprove) && decision != string(identity.DesktopAuthorizationDeny)) {
		return "", fmt.Errorf("%w: desktop authorization decision must be approve or deny", control.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w: desktop authorization decision must contain one JSON object", control.ErrInvalid)
	}
	return decision, nil
}

func decodeDesktopAuthorizationComplete(r *http.Request) (desktopAuthorizationCompleteRequest, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: malformed desktop authorization completion", control.ErrInvalid)
	}
	input := desktopAuthorizationCompleteRequest{}
	seenRequestID, seenPollSecret := false, false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: malformed desktop authorization completion", control.ErrInvalid)
		}
		switch key {
		case "request_id":
			if seenRequestID || decoder.Decode(&input.RequestID) != nil {
				return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: desktop authorization completion has an invalid request_id", control.ErrInvalid)
			}
			seenRequestID = true
		case "poll_secret":
			if seenPollSecret || decoder.Decode(&input.PollSecret) != nil {
				return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: desktop authorization completion has an invalid poll_secret", control.ErrInvalid)
			}
			seenPollSecret = true
		default:
			return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: desktop authorization completion contains an unsupported field", control.ErrInvalid)
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || !seenRequestID || !seenPollSecret {
		return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: desktop authorization completion requires request_id and poll_secret", control.ErrInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return desktopAuthorizationCompleteRequest{}, fmt.Errorf("%w: desktop authorization completion must contain one JSON object", control.ErrInvalid)
	}
	return input, nil
}
