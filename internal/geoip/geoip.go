// Package geoip provides IP-to-country lookup using MaxMind/DB-IP mmdb format.
package geoip

import (
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// Result holds the result of a GeoIP lookup.
type Result struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
}

// DB is a thread-safe wrapper around a MaxMind .mmdb reader.
type DB struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
}

// Open opens an existing .mmdb file.
func Open(path string) (*DB, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("geoip: database not found: %s", path)
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip: open %s: %w", path, err)
	}
	return &DB{reader: reader, path: path}, nil
}

// Lookup resolves an IP string to a country.
func (db *DB) Lookup(ipStr string) Result {
	unknown := Result{CountryCode: "XX", CountryName: "Unknown"}
	if db == nil {
		return unknown
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if db.reader == nil {
		return unknown
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return unknown
	}
	var rec record
	if err := db.reader.Lookup(ip, &rec); err != nil {
		return unknown
	}
	if rec.Country.ISOCode == "" {
		return unknown
	}
	name := rec.Country.Names["en"]
	if name == "" {
		name = rec.Country.ISOCode
	}
	return Result{CountryCode: rec.Country.ISOCode, CountryName: name}
}

// Close closes the underlying database reader.
func (db *DB) Close() error {
	if db == nil || db.reader == nil {
		return nil
	}
	return db.reader.Close()
}

// EnsureDB checks if the mmdb file exists at path; if not, downloads the free
// DB-IP Lite country database (no registration or key required).
func EnsureDB(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}

	now := time.Now().UTC()
	url := fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb.gz", now.Year(), now.Month())

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("geoip: mkdir: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("geoip: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip: download returned %d", resp.StatusCode)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("geoip: gunzip: %w", err)
	}
	defer gz.Close()

	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("geoip: create temp: %w", err)
	}

	if _, err := io.Copy(f, gz); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("geoip: write: %w", err)
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("geoip: rename: %w", err)
	}
	return nil
}
