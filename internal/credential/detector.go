// Package credential detects credential stuffing and brute force attacks.
package credential

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Event represents a login attempt observation.
type Event struct {
	IP       string    `json:"ip"`
	Path     string    `json:"path"`
	Status   int       `json:"status"`
	Time     time.Time `json:"time"`
}

// Stats holds credential protection statistics.
type Stats struct {
	TotalAttempts      int64 `json:"total_attempts"`
	BlockedIPs         int   `json:"blocked_ips"`
	ActiveTrackedIPs   int   `json:"active_tracked_ips"`
	AttacksDetected    int64 `json:"attacks_detected"`
}

// Detector monitors login endpoints for credential attacks.
type Detector struct {
	mu          sync.Mutex
	loginPaths  []string
	maxPerIP    int // max attempts per IP per hour
	maxPerUser  int // max attempts per username per hour

	// Per-IP tracking: IP → list of attempt times
	ipAttempts  map[string][]time.Time

	// Per-username tracking: username → list of attempt times
	userAttempts map[string][]time.Time

	// Blocked IPs
	blockedIPs  map[string]time.Time

	// Counters
	totalAttempts  int64
	attacksDetected int64

	// Callback
	OnBlock func(ip string, reason string)

	stopCh chan struct{}
}

// New creates a credential stuffing detector.
func New(loginPaths []string, maxPerIP, maxPerUser int) *Detector {
	d := &Detector{
		loginPaths:   loginPaths,
		maxPerIP:     maxPerIP,
		maxPerUser:   maxPerUser,
		ipAttempts:   make(map[string][]time.Time),
		userAttempts: make(map[string][]time.Time),
		blockedIPs:   make(map[string]time.Time),
		stopCh:       make(chan struct{}),
	}
	go d.cleanup()
	return d
}

// Middleware returns an HTTP middleware that monitors login endpoints.
func (d *Detector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only monitor POST requests to login paths
		if r.Method != http.MethodPost || !d.isLoginPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)

		// Check if IP is already blocked
		if d.isBlocked(ip) {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Extract username from request body for per-user tracking
		username := ""
		if r.Body != nil && d.maxPerUser > 0 {
			body, err := io.ReadAll(r.Body)
			if err == nil && len(body) > 0 {
				username = extractUsername(body, r.Header.Get("Content-Type"))
				// Restore the body for downstream handlers
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Record per-IP attempt
		blocked := d.recordAttempt(ip)
		if blocked {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}

		// Record per-username attempt
		if username != "" {
			if d.recordUserAttempt(ip, username) {
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		// Use response recorder to check status code
		rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(rec, r)
	})
}

func (d *Detector) isLoginPath(path string) bool {
	lower := strings.ToLower(path)
	for _, lp := range d.loginPaths {
		if strings.HasPrefix(lower, strings.ToLower(lp)) {
			return true
		}
	}
	return false
}

func (d *Detector) isBlocked(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	blockedAt, ok := d.blockedIPs[ip]
	if !ok {
		return false
	}
	// Block lasts 1 hour
	if time.Since(blockedAt) > time.Hour {
		delete(d.blockedIPs, ip)
		return false
	}
	return true
}

// recordAttempt records a login attempt and returns true if the IP should be blocked.
func (d *Detector) recordAttempt(ip string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.totalAttempts++
	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)

	// Get or create IP attempt list
	attempts := d.ipAttempts[ip]

	// Slide window
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	d.ipAttempts[ip] = valid

	// Check if over limit
	if len(valid) > d.maxPerIP {
		d.blockedIPs[ip] = now
		d.attacksDetected++
		if d.OnBlock != nil {
			go d.OnBlock(ip, "credential_stuffing")
		}
		return true
	}

	return false
}

// recordUserAttempt records a per-username login attempt and returns true if blocked.
func (d *Detector) recordUserAttempt(ip, username string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-1 * time.Hour)

	attempts := d.userAttempts[username]
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	d.userAttempts[username] = valid

	if len(valid) > d.maxPerUser {
		d.blockedIPs[ip] = now
		d.attacksDetected++
		if d.OnBlock != nil {
			go d.OnBlock(ip, "credential_stuffing_per_user:"+username)
		}
		return true
	}
	return false
}

// extractUsername tries to extract a username from a POST body.
// Supports form-encoded and JSON payloads.
func extractUsername(body []byte, contentType string) string {
	ct := strings.ToLower(contentType)

	// JSON body
	if strings.Contains(ct, "application/json") {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			for _, key := range []string{"username", "email", "user", "login", "name"} {
				if val, ok := payload[key]; ok {
					if s, ok := val.(string); ok && s != "" {
						return s
					}
				}
			}
		}
		return ""
	}

	// Form-encoded body
	if strings.Contains(ct, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err == nil {
			for _, key := range []string{"username", "email", "user", "login", "name"} {
				if val := values.Get(key); val != "" {
					return val
				}
			}
		}
	}

	return ""
}

// GetStats returns current credential protection stats.
func (d *Detector) GetStats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()

	return Stats{
		TotalAttempts:    d.totalAttempts,
		BlockedIPs:       len(d.blockedIPs),
		ActiveTrackedIPs: len(d.ipAttempts),
		AttacksDetected:  d.attacksDetected,
	}
}

// cleanup removes expired entries every 10 minutes.
func (d *Detector) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.mu.Lock()
			cutoff := time.Now().Add(-2 * time.Hour)
			for ip, attempts := range d.ipAttempts {
				if len(attempts) > 0 && attempts[len(attempts)-1].Before(cutoff) {
					delete(d.ipAttempts, ip)
				}
			}
			for user, attempts := range d.userAttempts {
				if len(attempts) > 0 && attempts[len(attempts)-1].Before(cutoff) {
					delete(d.userAttempts, user)
				}
			}
			for ip, blockedAt := range d.blockedIPs {
				if time.Since(blockedAt) > time.Hour {
					delete(d.blockedIPs, ip)
				}
			}
			d.mu.Unlock()
		case <-d.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (d *Detector) Stop() {
	close(d.stopCh)
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
