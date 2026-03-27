// Package threatfeed provides threat intelligence feed integration.
// Downloads and caches IPs from Spamhaus DROP, Emerging Threats, FireHOL, etc.
package threatfeed

import (
	"net/http"
	"sync"
	"time"
)

// Manager coordinates threat feed downloads and provides lookup.
type Manager struct {
	mu       sync.RWMutex
	cache    *IPCache
	sources  []Source
	client   *http.Client
	interval time.Duration

	// Stats
	lastUpdate    time.Time
	lastResults   []FetchResult
	blockedByFeed int64

	stopCh chan struct{}
}

// Config holds threat feed configuration.
type Config struct {
	Enabled  bool
	Interval time.Duration // how often to refresh feeds
	Sources  []Source      // nil = use defaults
}

// New creates a threat feed manager.
func New(cfg Config) *Manager {
	sources := cfg.Sources
	if len(sources) == 0 {
		sources = DefaultSources()
	}
	interval := cfg.Interval
	if interval == 0 {
		interval = time.Hour
	}

	m := &Manager{
		cache:   NewIPCache(),
		sources: sources,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		interval: interval,
		stopCh:   make(chan struct{}),
	}
	return m
}

// Start begins the background feed updater.
func (m *Manager) Start() {
	// Initial fetch
	go m.Update()

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.Update()
			case <-m.stopCh:
				return
			}
		}
	}()
}

// Stop stops the background updater.
func (m *Manager) Stop() {
	close(m.stopCh)
}

// Update fetches all sources and updates the cache.
func (m *Manager) Update() {
	results := make([]FetchResult, 0, len(m.sources))
	for _, src := range m.sources {
		result := FetchSource(src, m.cache, m.client)
		results = append(results, result)
	}

	// Cleanup expired entries
	m.cache.Cleanup()

	m.mu.Lock()
	m.lastUpdate = time.Now()
	m.lastResults = results
	m.mu.Unlock()
}

// IsBlocked checks if an IP is in any threat feed.
func (m *Manager) IsBlocked(ip string) (bool, string) {
	return m.cache.Contains(ip)
}

// RecordBlock increments the blocked-by-feed counter.
func (m *Manager) RecordBlock() {
	m.mu.Lock()
	m.blockedByFeed++
	m.mu.Unlock()
}

// Middleware returns an HTTP middleware that blocks threat-listed IPs.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)
		if blocked, source := m.IsBlocked(ip); blocked {
			m.RecordBlock()
			w.Header().Set("X-Blocked-By", "threatfeed:"+source)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// GetStatus returns the current threat feed status.
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cacheStats := m.cache.Stats()
	return Status{
		Enabled:       true,
		LastUpdate:    m.lastUpdate,
		NextUpdate:    m.lastUpdate.Add(m.interval),
		TotalEntries:  cacheStats.TotalIPs + cacheStats.TotalCIDRs,
		BlockedByFeed: m.blockedByFeed,
		Sources:       m.lastResults,
		CacheStats:    cacheStats,
	}
}

// Status holds threat feed status information.
type Status struct {
	Enabled       bool          `json:"enabled"`
	LastUpdate    time.Time     `json:"last_update"`
	NextUpdate    time.Time     `json:"next_update"`
	TotalEntries  int           `json:"total_entries"`
	BlockedByFeed int64         `json:"blocked_by_feed"`
	Sources       []FetchResult `json:"sources"`
	CacheStats    CacheStats    `json:"cache_stats"`
}

func extractClientIP(r *http.Request) string {
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
