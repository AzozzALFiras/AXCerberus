// Package bot — HTTP middleware for bot enforcement.
package bot

import (
	"net/http"
)

// Middleware returns an HTTP middleware that enforces bot detection.
// - Malicious bots (score >= 95) are blocked with 403.
// - Suspicious bots (score >= 70) receive a rate-limit warning header.
// - Verified bots and humans pass through normally.
func (d *Detector) Middleware(next http.Handler) http.Handler {
	if d == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := d.Detect(r.Header.Get("User-Agent"))

		// Block malicious bots outright
		if result.Score >= 95 {
			w.Header().Set("X-Bot-Block", result.BotName)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Tag suspicious bots for downstream modules (rate limiter, WAF)
		if result.Score >= 70 {
			r.Header.Set("X-Bot-Score", "suspicious")
			r.Header.Set("X-Bot-Name", result.BotName)
		}

		next.ServeHTTP(w, r)
	})
}
