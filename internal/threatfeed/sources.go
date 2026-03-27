package threatfeed

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Source defines a threat intelligence feed source.
type Source struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Format string `json:"format"` // "plain", "csv_ip_first", "drop"
	TTL    time.Duration
}

// FetchResult holds the result of fetching a single source.
type FetchResult struct {
	Source  string `json:"source"`
	Count   int    `json:"count"`
	Error   string `json:"error,omitempty"`
	Elapsed int64  `json:"elapsed_ms"`
}

// DefaultSources returns the built-in threat feed sources.
func DefaultSources() []Source {
	return []Source{
		{
			Name:   "spamhaus_drop",
			URL:    "https://www.spamhaus.org/drop/drop.txt",
			Format: "drop",
			TTL:    24 * time.Hour,
		},
		{
			Name:   "spamhaus_edrop",
			URL:    "https://www.spamhaus.org/drop/edrop.txt",
			Format: "drop",
			TTL:    24 * time.Hour,
		},
		{
			Name:   "emerging_threats",
			URL:    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
			Format: "plain",
			TTL:    12 * time.Hour,
		},
		{
			Name:   "firehol_level1",
			URL:    "https://iplists.firehol.org/files/firehol_level1.netset",
			Format: "plain",
			TTL:    12 * time.Hour,
		},
	}
}

// FetchSource downloads and parses a single threat feed.
func FetchSource(src Source, cache *IPCache, client *http.Client) FetchResult {
	start := time.Now()
	result := FetchResult{Source: src.Name}

	resp, err := client.Get(src.URL)
	if err != nil {
		result.Error = fmt.Sprintf("fetch: %v", err)
		result.Elapsed = time.Since(start).Milliseconds()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("http %d", resp.StatusCode)
		result.Elapsed = time.Since(start).Milliseconds()
		return result
	}

	count := 0
	switch src.Format {
	case "drop":
		count = parseDROP(resp.Body, src.Name, src.TTL, cache)
	case "csv_ip_first":
		count = parseCSVIPFirst(resp.Body, src.Name, src.TTL, cache)
	default: // "plain"
		count = parsePlainIP(resp.Body, src.Name, src.TTL, cache)
	}

	result.Count = count
	result.Elapsed = time.Since(start).Milliseconds()
	return result
}

// parsePlainIP parses one IP or CIDR per line, skipping comments.
func parsePlainIP(r io.Reader, source string, ttl time.Duration, cache *IPCache) int {
	scanner := bufio.NewScanner(r)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if isValidIPOrCIDR(line) {
			cache.Add(line, source, ttl)
			count++
		}
	}
	return count
}

// parseDROP parses Spamhaus DROP format: "CIDR ; SBLxxxxxx"
func parseDROP(r io.Reader, source string, ttl time.Duration, cache *IPCache) int {
	scanner := bufio.NewScanner(r)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		// Format: "1.2.3.0/24 ; SBL123456"
		parts := strings.SplitN(line, ";", 2)
		cidr := strings.TrimSpace(parts[0])
		if isValidIPOrCIDR(cidr) {
			cache.Add(cidr, source, ttl)
			count++
		}
	}
	return count
}

// parseCSVIPFirst parses CSV where first field is IP/CIDR.
func parseCSVIPFirst(r io.Reader, source string, ttl time.Duration, cache *IPCache) int {
	scanner := bufio.NewScanner(r)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if isValidIPOrCIDR(ip) {
			cache.Add(ip, source, ttl)
			count++
		}
	}
	return count
}

func isValidIPOrCIDR(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}
