// Package headers adds security response headers to all proxied responses.
package headers

import "net/http"

// Config holds security header configuration.
type Config struct {
	Enabled       bool
	XFrameOptions string // "DENY", "SAMEORIGIN", or empty to skip
	CSPPolicy     string // Content-Security-Policy value, empty to skip
	HSTS          bool   // add Strict-Transport-Security when request is HTTPS
}

// Hardener adds security headers to HTTP responses.
type Hardener struct {
	cfg Config
}

// New creates a response header hardener.
func New(cfg Config) *Hardener {
	return &Hardener{cfg: cfg}
}

// Middleware returns an HTTP middleware that adds security headers.
func (h *Hardener) Middleware(next http.Handler) http.Handler {
	if !h.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := w.Header()

		// Prevent MIME type sniffing
		hdr.Set("X-Content-Type-Options", "nosniff")

		// Disable XSS auditor (modern browsers deprecated it; 0 is recommended)
		hdr.Set("X-XSS-Protection", "0")

		// Referrer policy
		hdr.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy — restrict sensitive browser APIs
		hdr.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")

		// Clickjacking protection
		if h.cfg.XFrameOptions != "" {
			hdr.Set("X-Frame-Options", h.cfg.XFrameOptions)
		}

		// Content Security Policy
		if h.cfg.CSPPolicy != "" {
			hdr.Set("Content-Security-Policy", h.cfg.CSPPolicy)
		}

		// HSTS (only if the original request came over TLS or via TLS-terminated proxy)
		if h.cfg.HSTS && (r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https") {
			hdr.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}
