package dlp

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Mode controls DLP action on detection.
type Mode string

const (
	ModeBlock Mode = "block"
	ModeMask  Mode = "mask"
	ModeLog   Mode = "log"
)

// Event records a DLP detection.
type Event struct {
	Type    PatternType `json:"type"`
	URI     string      `json:"uri"`
	IP      string      `json:"ip"`
	Matches int         `json:"matches"`
}

// Scanner scans HTTP response bodies for sensitive data.
type Scanner struct {
	mode       Mode
	creditCard bool
	apiKeys    bool
	stackTrace bool
	patterns   []DetectionPattern

	// Callback for detected events
	OnDetect func(event Event)
}

// NewScanner creates a DLP scanner.
func NewScanner(mode string, creditCards, apiKeys, stackTraces bool) *Scanner {
	s := &Scanner{
		mode:       Mode(mode),
		creditCard: creditCards,
		apiKeys:    apiKeys,
		stackTrace: stackTraces,
	}
	s.buildPatterns()
	return s
}

func (s *Scanner) buildPatterns() {
	s.patterns = nil
	if s.creditCard {
		s.patterns = append(s.patterns, CreditCardPatterns...)
	}
	if s.apiKeys {
		s.patterns = append(s.patterns, APIKeyPatterns...)
	}
	if s.stackTrace {
		s.patterns = append(s.patterns, StackTracePatterns...)
		s.patterns = append(s.patterns, DBErrorPatterns...)
	}
	// Always check for internal IPs
	s.patterns = append(s.patterns, InternalIPPattern)
}

// Middleware returns an HTTP middleware that scans response bodies.
func (s *Scanner) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Buffer the response to scan it
		rec := &responseBuffer{
			header: make(http.Header),
			buf:    &bytes.Buffer{},
			code:   http.StatusOK,
		}
		next.ServeHTTP(rec, r)

		// Skip binary content types
		ct := rec.header.Get("Content-Type")
		if isBinaryContent(ct) || rec.buf.Len() == 0 {
			copyResponse(w, rec)
			return
		}

		// Scan response body
		body := rec.buf.Bytes()
		matches := s.scan(body)

		if len(matches) > 0 {
			if s.OnDetect != nil {
				s.OnDetect(Event{
					Type:    matches[0].Type,
					URI:     r.URL.Path,
					IP:      r.RemoteAddr,
					Matches: len(matches),
				})
			}

			switch s.mode {
			case ModeBlock:
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("Request blocked: sensitive data detected in response"))
				return
			case ModeMask:
				masked := s.mask(body, matches)
				rec.buf = bytes.NewBuffer(masked)
				rec.header.Set("Content-Length", fmt.Sprintf("%d", len(masked)))
			// ModeLog: fall through to normal response
			}
		}

		copyResponse(w, rec)
	})
}

// scan checks the body against all configured patterns.
func (s *Scanner) scan(body []byte) []Match {
	var matches []Match
	text := string(body)

	for _, p := range s.patterns {
		locs := p.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			matched := text[loc[0]:loc[1]]

			// For credit cards, validate with Luhn
			if p.Type == PatternCreditCard {
				digits := strings.Map(func(r rune) rune {
					if r >= '0' && r <= '9' {
						return r
					}
					return -1
				}, matched)
				if !LuhnValid(digits) {
					continue
				}
			}

			// Redact the matched value for logging
			redacted := redact(matched)
			matches = append(matches, Match{
				Type:   p.Type,
				Value:  redacted,
				Offset: loc[0],
			})
		}
	}
	return matches
}

// mask replaces detected values with [REDACTED] in the body.
func (s *Scanner) mask(body []byte, matches []Match) []byte {
	text := string(body)
	for _, p := range s.patterns {
		text = p.Pattern.ReplaceAllString(text, "[REDACTED]")
	}
	return []byte(text)
}

// Scan exports scanning for testing purposes.
func (s *Scanner) Scan(body []byte) []Match {
	return s.scan(body)
}

func redact(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

func isBinaryContent(ct string) bool {
	lower := strings.ToLower(ct)
	binaryPrefixes := []string{
		"image/", "video/", "audio/", "application/octet-stream",
		"application/zip", "application/gzip", "application/pdf",
		"application/wasm", "font/",
	}
	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

type responseBuffer struct {
	header http.Header
	buf    *bytes.Buffer
	code   int
}

func (r *responseBuffer) Header() http.Header         { return r.header }
func (r *responseBuffer) WriteHeader(code int)        { r.code = code }
func (r *responseBuffer) Write(b []byte) (int, error) { return r.buf.Write(b) }

func copyResponse(w http.ResponseWriter, rec *responseBuffer) {
	for k, vals := range rec.header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.code)
	io.Copy(w, rec.buf)
}
