// Package honeypot implements trap endpoints that detect and block attackers.
package honeypot

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HitRecord stores information about a honeypot access.
type HitRecord struct {
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	UserAgent string    `json:"user_agent"`
	Headers   http.Header `json:"headers"`
	Body      string    `json:"body,omitempty"`
	Time      time.Time `json:"time"`
}

// Engine manages honeypot trap paths and records attacker interactions.
type Engine struct {
	mu        sync.RWMutex
	traps     map[string]bool
	autoBlock bool
	hits      []HitRecord // ring buffer
	maxHits   int
	blockedIPs map[string]time.Time

	// Callback for blocking IPs (set by proxy)
	OnBlock func(ip string)
}

// New creates a honeypot engine with the given trap paths.
func New(paths []string, autoBlock bool) *Engine {
	traps := make(map[string]bool, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p != "" {
			traps[strings.ToLower(p)] = true
		}
	}
	return &Engine{
		traps:      traps,
		autoBlock:  autoBlock,
		maxHits:    1000,
		blockedIPs: make(map[string]time.Time),
	}
}

// Middleware returns an HTTP middleware that intercepts honeypot paths.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(r.URL.Path)

		// Check if this path is a trap
		if !e.isTrap(path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)

		// Record the hit
		hit := HitRecord{
			IP:        ip,
			Path:      r.URL.Path,
			Method:    r.Method,
			UserAgent: r.Header.Get("User-Agent"),
			Headers:   r.Header.Clone(),
			Time:      time.Now(),
		}
		e.recordHit(hit)

		// Auto-block the IP immediately
		if e.autoBlock {
			e.mu.Lock()
			e.blockedIPs[ip] = time.Now()
			e.mu.Unlock()
			if e.OnBlock != nil {
				e.OnBlock(ip)
			}
			// Block immediately — do not serve fake content
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// If auto-block is disabled, serve a fake response to waste attacker's time
		serveFakePage(w, r.URL.Path)
	})
}

// IsTrap checks if a path is a registered trap.
func (e *Engine) isTrap(path string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Exact match
	if e.traps[path] {
		return true
	}

	// Check prefix match for directory traps
	for trap := range e.traps {
		if strings.HasPrefix(path, trap) {
			return true
		}
	}
	return false
}

func (e *Engine) recordHit(hit HitRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.hits) >= e.maxHits {
		// Ring buffer: overwrite oldest
		e.hits = e.hits[1:]
	}
	e.hits = append(e.hits, hit)
}

// GetHits returns the most recent honeypot hits.
func (e *Engine) GetHits(limit int) []HitRecord {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if limit <= 0 || limit > len(e.hits) {
		limit = len(e.hits)
	}
	start := len(e.hits) - limit
	result := make([]HitRecord, limit)
	copy(result, e.hits[start:])
	return result
}

// GetBlockedIPs returns IPs blocked by honeypot.
func (e *Engine) GetBlockedIPs() map[string]time.Time {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make(map[string]time.Time, len(e.blockedIPs))
	for k, v := range e.blockedIPs {
		cp[k] = v
	}
	return cp
}

// AddTrap adds a new trap path at runtime.
func (e *Engine) AddTrap(path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.traps[strings.ToLower(strings.TrimSpace(path))] = true
}

// TotalHits returns the total number of recorded hits.
func (e *Engine) TotalHits() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.hits)
}

func extractIP(r *http.Request) string {
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
