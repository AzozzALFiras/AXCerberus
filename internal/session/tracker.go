// Package session provides cookie-based session tracking and
// account takeover (ATO) detection.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Config holds session tracking configuration.
type Config struct {
	Enabled       bool
	CookieName    string        // session cookie to track (default: common names)
	MaxPerSession int           // max requests per session per minute
	ATOEnabled    bool          // detect impossible travel / device changes
}

// Tracker monitors user sessions for anomalous behavior.
type Tracker struct {
	cfg      Config
	mu       sync.Mutex
	sessions map[string]*sessionState

	// Stats
	activeSessions int64
	atoDetected    int64
}

type sessionState struct {
	fingerprint string // hash of UA + accept-language
	ips         []ipSighting
	reqCount    int
	lastMinute  time.Time
	minuteCount int
	firstSeen   time.Time
	lastSeen    time.Time
}

type ipSighting struct {
	ip   string
	time time.Time
}

// New creates a session tracker.
func New(cfg Config) *Tracker {
	if cfg.CookieName == "" {
		cfg.CookieName = "" // will check common names
	}
	if cfg.MaxPerSession == 0 {
		cfg.MaxPerSession = 120
	}
	t := &Tracker{
		cfg:      cfg,
		sessions: make(map[string]*sessionState),
	}
	go t.cleanup()
	return t
}

// Middleware returns an HTTP middleware that tracks sessions.
func (t *Tracker) Middleware(next http.Handler) http.Handler {
	if !t.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := t.extractSessionID(r)
		if sessionID == "" {
			next.ServeHTTP(w, r)
			return
		}

		ip := extractIP(r)
		fp := clientFingerprint(r)
		anomaly := t.recordSession(sessionID, ip, fp)

		if anomaly != "" {
			r.Header.Set("X-Session-Anomaly", anomaly)
		}

		next.ServeHTTP(w, r)
	})
}

// recordSession records a session activity and returns an anomaly type if detected.
func (t *Tracker) recordSession(id, ip, fingerprint string) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	currentMinute := now.Truncate(time.Minute)

	sess, ok := t.sessions[id]
	if !ok {
		t.sessions[id] = &sessionState{
			fingerprint: fingerprint,
			ips:         []ipSighting{{ip: ip, time: now}},
			reqCount:    1,
			lastMinute:  currentMinute,
			minuteCount: 1,
			firstSeen:   now,
			lastSeen:    now,
		}
		t.activeSessions++
		return ""
	}

	sess.lastSeen = now
	sess.reqCount++

	// Per-minute rate check
	if currentMinute.Equal(sess.lastMinute) {
		sess.minuteCount++
	} else {
		sess.lastMinute = currentMinute
		sess.minuteCount = 1
	}

	anomaly := ""

	// Check for device fingerprint change (possible ATO)
	if t.cfg.ATOEnabled && sess.fingerprint != "" && fingerprint != sess.fingerprint {
		t.atoDetected++
		anomaly = "device_change"
	}

	// Check for IP change (possible ATO / impossible travel)
	if t.cfg.ATOEnabled && len(sess.ips) > 0 {
		lastIP := sess.ips[len(sess.ips)-1]
		if lastIP.ip != ip {
			timeDiff := now.Sub(lastIP.time)
			if timeDiff < 5*time.Minute {
				// IP changed within 5 minutes — suspicious
				t.atoDetected++
				if anomaly == "" {
					anomaly = "impossible_travel"
				}
			}
			sess.ips = append(sess.ips, ipSighting{ip: ip, time: now})
			// Keep last 10 IPs
			if len(sess.ips) > 10 {
				sess.ips = sess.ips[len(sess.ips)-10:]
			}
		}
	}

	// Rate limit check
	if sess.minuteCount > t.cfg.MaxPerSession {
		if anomaly == "" {
			anomaly = "session_rate_exceeded"
		}
	}

	return anomaly
}

// extractSessionID finds a session identifier from cookies.
func (t *Tracker) extractSessionID(r *http.Request) string {
	if t.cfg.CookieName != "" {
		if c, err := r.Cookie(t.cfg.CookieName); err == nil {
			return hashValue(c.Value)
		}
		return ""
	}
	// Check common session cookie names
	for _, name := range []string{
		"PHPSESSID", "JSESSIONID", "session_id", "sid",
		"connect.sid", "_session_id", "laravel_session",
		"wp_sec", "auth_token", "token",
	} {
		if c, err := r.Cookie(name); err == nil && c.Value != "" {
			return hashValue(c.Value)
		}
	}
	return ""
}

// GetStats returns session tracking stats.
func (t *Tracker) GetStats() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]any{
		"enabled":          t.cfg.Enabled,
		"active_sessions":  len(t.sessions),
		"ato_detected":     t.atoDetected,
	}
}

func (t *Tracker) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		t.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for id, sess := range t.sessions {
			if sess.lastSeen.Before(cutoff) {
				delete(t.sessions, id)
			}
		}
		t.activeSessions = int64(len(t.sessions))
		t.mu.Unlock()
	}
}

func clientFingerprint(r *http.Request) string {
	ua := r.Header.Get("User-Agent")
	lang := r.Header.Get("Accept-Language")
	enc := r.Header.Get("Accept-Encoding")
	return hashValue(ua + "|" + lang + "|" + enc)
}

func hashValue(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func extractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Real-IP"); xff != "" {
		return xff
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}
	for i := len(r.RemoteAddr) - 1; i >= 0; i-- {
		if r.RemoteAddr[i] == ':' {
			return r.RemoteAddr[:i]
		}
	}
	return r.RemoteAddr
}
