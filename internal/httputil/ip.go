// Package httputil provides shared HTTP utilities for all AXCerberus modules.
package httputil

import (
	"net"
	"net/http"
	"strings"
)

// RealIP extracts the client IP from an HTTP request.
// Priority: X-Forwarded-For (first IP) → X-Real-IP → RemoteAddr.
// All modules MUST use this function for consistent IP attribution.
func RealIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
