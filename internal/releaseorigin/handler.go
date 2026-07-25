package releaseorigin

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
)

const (
	channelCacheControl   = "public, max-age=30, must-revalidate, no-transform"
	immutableCacheControl = "public, max-age=31536000, immutable, no-transform"
)

func (store *Store) Handler() http.Handler {
	return http.HandlerFunc(store.serveHTTP)
}

func (store *Store) serveHTTP(w http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(w.Header())
	if request.URL.RawQuery != "" || request.URL.Fragment != "" || request.URL.RawPath != "" {
		writeStatus(w, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeStatus(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	switch request.URL.Path {
	case "/healthz":
		writeStatus(w, http.StatusOK, "ok")
		return
	case "/readyz":
		if err := store.CheckReadiness(); err != nil {
			writeStatus(w, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(w, http.StatusOK, "ready")
		return
	}
	if err := validateObjectPath(request.URL.Path); err != nil {
		writeStatus(w, http.StatusNotFound, "not_found")
		return
	}

	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.closed {
		writeStatus(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	object := store.objects[request.URL.Path]
	if object == nil {
		writeStatus(w, http.StatusNotFound, "not_found")
		return
	}
	current, err := object.file.Stat()
	if err != nil || !sameObjectFile(object.identity.info, current) {
		writeStatus(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	cacheControl := immutableCacheControl
	if object.metadata.Cache == CacheChannel {
		cacheControl = channelCacheControl
	}
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Type", object.metadata.ContentType)
	w.Header().Set("ETag", object.etag)
	if request.Header.Get("If-None-Match") == object.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(object.metadata.Size, 10))
	w.WriteHeader(http.StatusOK)
	if request.Method == http.MethodHead {
		return
	}
	written, copyErr := io.CopyN(w, io.NewSectionReader(object.file, 0, object.metadata.Size), object.metadata.Size)
	final, statErr := object.file.Stat()
	if copyErr != nil || written != object.metadata.Size || statErr != nil || !sameObjectFile(object.identity.info, final) {
		panic(http.ErrAbortHandler)
	}
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Strict-Transport-Security", "max-age=31536000")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}

func writeStatus(w http.ResponseWriter, statusCode int, status string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(struct {
		Status string `json:"status"`
	}{Status: status})
}
