// Package anomaly provides baseline anomaly detection.
// It records per-endpoint request distributions and detects deviations.
package anomaly

import (
	"math"
	"net/http"
	"sync"
	"time"
)

// Config holds anomaly detection configuration.
type Config struct {
	Enabled          bool
	WindowMinutes    int     // baseline window size (default 60)
	DeviationFactor  float64 // multiplier for stddev to flag anomaly (default 3.0)
	MinSamples       int     // minimum samples before detection (default 100)
}

// Detector records request patterns and detects anomalies.
type Detector struct {
	cfg       Config
	mu        sync.Mutex
	endpoints map[string]*endpointBaseline

	// Stats
	anomaliesDetected int64
}

type endpointBaseline struct {
	// Sliding window of per-minute request counts
	minuteCounts []int
	currentMin   time.Time
	currentCount int

	// Body size tracking
	bodySizes []int64

	// Computed baseline
	meanRate   float64
	stddevRate float64
	samples    int
}

// New creates an anomaly detector.
func New(cfg Config) *Detector {
	if cfg.WindowMinutes == 0 {
		cfg.WindowMinutes = 60
	}
	if cfg.DeviationFactor == 0 {
		cfg.DeviationFactor = 3.0
	}
	if cfg.MinSamples == 0 {
		cfg.MinSamples = 100
	}
	d := &Detector{
		cfg:       cfg,
		endpoints: make(map[string]*endpointBaseline),
	}
	go d.recalcLoop()
	return d
}

// Middleware returns an HTTP middleware that records and checks traffic patterns.
func (d *Detector) Middleware(next http.Handler) http.Handler {
	if !d.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := normalizePath(r.URL.Path)
		isAnomaly := d.recordAndCheck(path, r.ContentLength)

		if isAnomaly {
			r.Header.Set("X-Anomaly-Detected", "true")
			// Don't block — just tag for downstream modules to use
		}

		next.ServeHTTP(w, r)
	})
}

// recordAndCheck records a request and returns true if it's anomalous.
func (d *Detector) recordAndCheck(path string, bodySize int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	currentMinute := now.Truncate(time.Minute)

	bl, ok := d.endpoints[path]
	if !ok {
		bl = &endpointBaseline{
			minuteCounts: make([]int, 0, d.cfg.WindowMinutes),
			bodySizes:    make([]int64, 0, 100),
			currentMin:   currentMinute,
		}
		d.endpoints[path] = bl
	}

	// Roll over minute if needed
	if currentMinute.After(bl.currentMin) {
		bl.minuteCounts = append(bl.minuteCounts, bl.currentCount)
		// Keep only the configured window
		if len(bl.minuteCounts) > d.cfg.WindowMinutes {
			bl.minuteCounts = bl.minuteCounts[len(bl.minuteCounts)-d.cfg.WindowMinutes:]
		}
		bl.currentCount = 0
		bl.currentMin = currentMinute
	}
	bl.currentCount++
	bl.samples++

	if bodySize > 0 {
		bl.bodySizes = append(bl.bodySizes, bodySize)
		if len(bl.bodySizes) > 1000 {
			bl.bodySizes = bl.bodySizes[len(bl.bodySizes)-1000:]
		}
	}

	// Check for anomaly
	if bl.samples < d.cfg.MinSamples || bl.stddevRate == 0 {
		return false
	}

	// Current rate is anomalous if > mean + factor * stddev
	threshold := bl.meanRate + d.cfg.DeviationFactor*bl.stddevRate
	if float64(bl.currentCount) > threshold && threshold > 0 {
		d.anomaliesDetected++
		return true
	}

	return false
}

// recalcLoop periodically recalculates baselines.
func (d *Detector) recalcLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		d.mu.Lock()
		for _, bl := range d.endpoints {
			if len(bl.minuteCounts) < 5 {
				continue
			}
			bl.meanRate, bl.stddevRate = meanAndStddev(bl.minuteCounts)
		}
		d.mu.Unlock()
	}
}

// GetStats returns anomaly detection stats.
func (d *Detector) GetStats() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]any{
		"enabled":            d.cfg.Enabled,
		"tracked_endpoints":  len(d.endpoints),
		"anomalies_detected": d.anomaliesDetected,
	}
}

func meanAndStddev(counts []int) (float64, float64) {
	n := float64(len(counts))
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, c := range counts {
		sum += float64(c)
	}
	mean := sum / n
	var variance float64
	for _, c := range counts {
		diff := float64(c) - mean
		variance += diff * diff
	}
	variance /= n
	return mean, math.Sqrt(variance)
}

// normalizePath reduces paths to a canonical form for grouping.
func normalizePath(path string) string {
	// Replace numeric path segments with {id}
	// e.g. /api/users/123/posts → /api/users/{id}/posts
	parts := make([]byte, 0, len(path))
	inNumeric := false
	for i := 0; i < len(path); i++ {
		c := path[i]
		if c == '/' {
			if inNumeric {
				parts = append(parts, "{id}"...)
				inNumeric = false
			}
			parts = append(parts, c)
			continue
		}
		if c >= '0' && c <= '9' && (i == 0 || path[i-1] == '/') {
			inNumeric = true
			continue
		}
		if inNumeric && c >= '0' && c <= '9' {
			continue
		}
		if inNumeric {
			// Not purely numeric — just a normal segment
			inNumeric = false
			// Rewind to include the digits we skipped
			j := i - 1
			for j >= 0 && path[j] != '/' {
				j--
			}
			parts = append(parts, path[j+1:i]...)
		}
		parts = append(parts, c)
	}
	if inNumeric {
		parts = append(parts, "{id}"...)
	}
	return string(parts)
}
