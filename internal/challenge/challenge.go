// Package challenge implements a JavaScript challenge system for bot mitigation.
// Similar to Cloudflare's "Under Attack Mode", it serves a JS computation page
// that must be solved before accessing the site.
package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	axhttp "axcerberus/internal/httputil"
)

// Config holds challenge system configuration.
type Config struct {
	Enabled   bool
	Duration  time.Duration // how long a solved challenge is valid
	Threshold int           // bot score threshold to trigger challenge
	Secret    []byte        // HMAC key for token signing
}

// System implements the JavaScript challenge middleware.
type System struct {
	cfg Config
}

// New creates a challenge system.
func New(cfg Config) *System {
	if len(cfg.Secret) == 0 {
		cfg.Secret = make([]byte, 32)
		rand.Read(cfg.Secret)
	}
	if cfg.Duration == 0 {
		cfg.Duration = time.Hour
	}
	if cfg.Threshold == 0 {
		cfg.Threshold = 60
	}
	return &System{cfg: cfg}
}

const cookieName = "axcerberus_challenge"

// Middleware returns an HTTP middleware that issues JS challenges.
func (s *System) Middleware(next http.Handler) http.Handler {
	if !s.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip static assets
		if isStaticAsset(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Check for valid challenge cookie
		cookie, err := r.Cookie(cookieName)
		if err == nil && s.validateToken(cookie.Value, axhttp.RealIP(r)) {
			next.ServeHTTP(w, r)
			return
		}

		// Check if bot score triggers challenge
		botScore := r.Header.Get("X-Bot-Score")
		if botScore != "suspicious" {
			// Not suspicious — pass through
			next.ServeHTTP(w, r)
			return
		}

		// Check for challenge solution submission
		if r.URL.Path == "/__axcerberus/challenge/verify" && r.Method == http.MethodPost {
			s.handleVerify(w, r)
			return
		}

		// Serve the challenge page
		s.serveChallenge(w, r)
	})
}

// handleVerify checks the submitted challenge solution.
func (s *System) handleVerify(w http.ResponseWriter, r *http.Request) {
	answer := r.FormValue("answer")
	nonce := r.FormValue("nonce")
	ip := axhttp.RealIP(r)

	// Verify: SHA256(nonce + ip) must start with "000000" (~16M operations)
	hash := sha256.Sum256([]byte(nonce + ip))
	hashHex := hex.EncodeToString(hash[:])

	if !strings.HasPrefix(hashHex, "000000") || answer != hashHex[:16] {
		http.Error(w, "Challenge failed", http.StatusForbidden)
		return
	}

	// Issue token cookie
	token := s.generateToken(ip)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.cfg.Duration.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect back to original page
	redirect := r.FormValue("redirect")
	if redirect == "" || !strings.HasPrefix(redirect, "/") {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// generateToken creates an HMAC-signed token for the given IP.
func (s *System) generateToken(ip string) string {
	expiry := time.Now().Add(s.cfg.Duration).Unix()
	payload := fmt.Sprintf("%s|%d", ip, expiry)
	mac := hmac.New(sha256.New, s.cfg.Secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s|%s", payload, sig)
}

// validateToken verifies an HMAC-signed token.
func (s *System) validateToken(token, ip string) bool {
	parts := strings.SplitN(token, "|", 3)
	if len(parts) != 3 {
		return false
	}
	tokenIP := parts[0]
	if tokenIP != ip {
		return false
	}
	var expiry int64
	if _, err := fmt.Sscanf(parts[1], "%d", &expiry); err != nil {
		return false
	}
	if time.Now().Unix() > expiry {
		return false
	}
	payload := fmt.Sprintf("%s|%s", parts[0], parts[1])
	mac := hmac.New(sha256.New, s.cfg.Secret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[2]), []byte(expectedSig))
}

func isStaticAsset(path string) bool {
	lower := strings.ToLower(path)
	exts := []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"}
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

