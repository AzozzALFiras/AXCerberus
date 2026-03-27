// Package threatfeed — in-memory IP set with TTL for threat intelligence data.
package threatfeed

import (
	"net"
	"sync"
	"time"
)

// IPCache is a thread-safe IP set with per-entry TTL.
type IPCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	nets    []netEntry
}

type cacheEntry struct {
	source    string
	expiresAt time.Time
}

type netEntry struct {
	net       *net.IPNet
	source    string
	expiresAt time.Time
}

// NewIPCache creates an empty IP cache.
func NewIPCache() *IPCache {
	return &IPCache{
		entries: make(map[string]cacheEntry),
		nets:    make([]netEntry, 0),
	}
}

// Add adds an IP or CIDR to the cache with a TTL.
func (c *IPCache) Add(ipOrCIDR, source string, ttl time.Duration) {
	exp := time.Now().Add(ttl)

	if _, cidr, err := net.ParseCIDR(ipOrCIDR); err == nil {
		c.mu.Lock()
		c.nets = append(c.nets, netEntry{net: cidr, source: source, expiresAt: exp})
		c.mu.Unlock()
		return
	}

	c.mu.Lock()
	c.entries[ipOrCIDR] = cacheEntry{source: source, expiresAt: exp}
	c.mu.Unlock()
}

// Contains checks if an IP is in the cache (not expired).
func (c *IPCache) Contains(ip string) (bool, string) {
	now := time.Now()

	c.mu.RLock()
	defer c.mu.RUnlock()

	if e, ok := c.entries[ip]; ok && e.expiresAt.After(now) {
		return true, e.source
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false, ""
	}
	for _, n := range c.nets {
		if n.expiresAt.After(now) && n.net.Contains(parsed) {
			return true, n.source
		}
	}

	return false, ""
}

// Size returns the number of entries (IPs + CIDRs).
func (c *IPCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries) + len(c.nets)
}

// Cleanup removes expired entries.
func (c *IPCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for ip, e := range c.entries {
		if e.expiresAt.Before(now) {
			delete(c.entries, ip)
			removed++
		}
	}

	valid := c.nets[:0]
	for _, n := range c.nets {
		if n.expiresAt.After(now) {
			valid = append(valid, n)
		} else {
			removed++
		}
	}
	c.nets = valid

	return removed
}

// Stats returns cache statistics.
func (c *IPCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	sources := make(map[string]int)
	now := time.Now()

	for _, e := range c.entries {
		if e.expiresAt.After(now) {
			sources[e.source]++
		}
	}
	for _, n := range c.nets {
		if n.expiresAt.After(now) {
			sources[n.source]++
		}
	}

	return CacheStats{
		TotalIPs:   len(c.entries),
		TotalCIDRs: len(c.nets),
		PerSource:  sources,
	}
}

// CacheStats holds cache statistics.
type CacheStats struct {
	TotalIPs   int            `json:"total_ips"`
	TotalCIDRs int            `json:"total_cidrs"`
	PerSource  map[string]int `json:"per_source"`
}
