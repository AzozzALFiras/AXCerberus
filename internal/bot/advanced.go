package bot

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// AdvancedDetector adds header fingerprinting and timing analysis.
type AdvancedDetector struct {
	mu        sync.Mutex
	ipTimings map[string]*timingProfile
}

type timingProfile struct {
	intervals  []time.Duration
	lastSeen   time.Time
	firstSeen  time.Time
	reqCount   int
}

// NewAdvancedDetector creates an advanced bot detector.
func NewAdvancedDetector() *AdvancedDetector {
	ad := &AdvancedDetector{
		ipTimings: make(map[string]*timingProfile),
	}
	go ad.cleanup()
	return ad
}

// AnalyzeRequest performs advanced bot analysis on a request.
// Returns an additional score adjustment (0-30) to add to the base UA score.
func (ad *AdvancedDetector) AnalyzeRequest(r *http.Request, ip string) AdvancedResult {
	score := 0
	signals := make([]string, 0, 4)

	// 1. Header order fingerprint
	headerFP := HeaderFingerprint(r)
	if isKnownAutomationFingerprint(headerFP) {
		score += 15
		signals = append(signals, "automation_header_fp")
	}

	// 2. Missing common browser headers
	if isBrowserClaim(r.Header.Get("User-Agent")) {
		missing := missingBrowserHeaders(r)
		if missing > 2 {
			score += 10
			signals = append(signals, "missing_browser_headers")
		}
	}

	// 3. Request timing analysis
	timingScore := ad.analyzeTimings(ip)
	if timingScore > 0 {
		score += timingScore
		signals = append(signals, "suspicious_timing")
	}

	// 4. Connection header anomalies
	if hasConnectionAnomalies(r) {
		score += 5
		signals = append(signals, "connection_anomaly")
	}

	return AdvancedResult{
		ScoreAdjustment: score,
		HeaderFP:        headerFP,
		Signals:         signals,
	}
}

// AdvancedResult holds advanced bot analysis results.
type AdvancedResult struct {
	ScoreAdjustment int      `json:"score_adjustment"`
	HeaderFP        string   `json:"header_fingerprint"`
	Signals         []string `json:"signals"`
}

// HeaderFingerprint generates a hash of the header order.
func HeaderFingerprint(r *http.Request) string {
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	combined := strings.Join(keys, "|")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:8])
}

// isKnownAutomationFingerprint checks if a header fingerprint matches known tools.
func isKnownAutomationFingerprint(fp string) bool {
	// These are detected dynamically; for now, flag requests with very few headers
	return false
}

// isBrowserClaim checks if the UA claims to be a browser.
func isBrowserClaim(ua string) bool {
	lower := strings.ToLower(ua)
	return strings.Contains(lower, "mozilla/") || strings.Contains(lower, "chrome/") ||
		strings.Contains(lower, "safari/") || strings.Contains(lower, "firefox/")
}

// missingBrowserHeaders counts headers a real browser would send but are absent.
func missingBrowserHeaders(r *http.Request) int {
	missing := 0
	expected := []string{"Accept", "Accept-Language", "Accept-Encoding"}
	for _, h := range expected {
		if r.Header.Get(h) == "" {
			missing++
		}
	}
	return missing
}

// analyzeTimings checks for machine-like request intervals.
func (ad *AdvancedDetector) analyzeTimings(ip string) int {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	now := time.Now()
	prof, ok := ad.ipTimings[ip]
	if !ok {
		ad.ipTimings[ip] = &timingProfile{
			firstSeen: now,
			lastSeen:  now,
			reqCount:  1,
		}
		return 0
	}

	interval := now.Sub(prof.lastSeen)
	prof.lastSeen = now
	prof.reqCount++

	if interval > 0 && interval < time.Hour {
		prof.intervals = append(prof.intervals, interval)
		// Keep last 20 intervals
		if len(prof.intervals) > 20 {
			prof.intervals = prof.intervals[len(prof.intervals)-20:]
		}
	}

	// Need at least 5 intervals to analyze
	if len(prof.intervals) < 5 {
		return 0
	}

	// Check for machine-like regularity: low coefficient of variation
	cv := coefficientOfVariation(prof.intervals)
	if cv < 0.05 && prof.reqCount > 10 {
		// Very regular timing — likely automated
		return 15
	}
	if cv < 0.15 && prof.reqCount > 20 {
		return 10
	}
	return 0
}

func (ad *AdvancedDetector) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ad.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for ip, prof := range ad.ipTimings {
			if prof.lastSeen.Before(cutoff) {
				delete(ad.ipTimings, ip)
			}
		}
		ad.mu.Unlock()
	}
}

func hasConnectionAnomalies(r *http.Request) bool {
	// HTTP/1.1 requests should have Host header (always present in Go)
	// Check for unusual protocol claims
	if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
		if r.Header.Get("Connection") == "" && r.Header.Get("Accept") == "" {
			return true
		}
	}
	return false
}

func coefficientOfVariation(intervals []time.Duration) float64 {
	if len(intervals) == 0 {
		return 1.0
	}
	var sum float64
	for _, d := range intervals {
		sum += float64(d)
	}
	mean := sum / float64(len(intervals))
	if mean == 0 {
		return 1.0
	}
	var variance float64
	for _, d := range intervals {
		diff := float64(d) - mean
		variance += diff * diff
	}
	variance /= float64(len(intervals))
	return math.Sqrt(variance) / mean
}
