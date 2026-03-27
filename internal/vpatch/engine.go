// Package vpatch provides virtual patching for known CVEs.
// Virtual patches are temporary WAF rules that block exploitation
// of known vulnerabilities until the software is updated.
package vpatch

import (
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Patch represents a virtual patch rule.
type Patch struct {
	ID          string    `json:"id"`
	CVE         string    `json:"cve"`
	Description string    `json:"description"`
	PathPattern string    `json:"path_pattern"`
	Method      string    `json:"method,omitempty"` // empty = all methods
	BodyPattern string    `json:"body_pattern,omitempty"`
	HeaderCheck string    `json:"header_check,omitempty"`
	Action      string    `json:"action"` // "block", "log"
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Enabled     bool      `json:"enabled"`

	compiledPath *regexp.Regexp
	compiledBody *regexp.Regexp
}

// Engine manages virtual patches.
type Engine struct {
	mu       sync.RWMutex
	patches  []Patch
	filePath string

	// Stats
	blocked int64
	logged  int64
}

// New creates a virtual patching engine.
func New(patchFile string) *Engine {
	e := &Engine{
		patches:  make([]Patch, 0),
		filePath: patchFile,
	}
	e.loadFromFile()
	return e
}

// Middleware returns an HTTP middleware that enforces virtual patches.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if patch, matched := e.matchRequest(r); matched {
			if patch.Action == "block" {
				e.mu.Lock()
				e.blocked++
				e.mu.Unlock()
				w.Header().Set("X-Blocked-By", "vpatch:"+patch.CVE)
				http.Error(w, "Forbidden — Virtual Patch: "+patch.CVE, http.StatusForbidden)
				return
			}
			// Action "log" — just tag and pass through
			e.mu.Lock()
			e.logged++
			e.mu.Unlock()
			r.Header.Set("X-VPatch-Match", patch.CVE)
		}
		next.ServeHTTP(w, r)
	})
}

// matchRequest checks if a request matches any active virtual patch.
func (e *Engine) matchRequest(r *http.Request) (Patch, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	for _, p := range e.patches {
		if !p.Enabled {
			continue
		}
		if !p.ExpiresAt.IsZero() && p.ExpiresAt.Before(now) {
			continue
		}
		if p.Method != "" && !strings.EqualFold(p.Method, r.Method) {
			continue
		}
		if p.compiledPath != nil && !p.compiledPath.MatchString(r.URL.Path) {
			continue
		}
		if p.HeaderCheck != "" {
			parts := strings.SplitN(p.HeaderCheck, ":", 2)
			if len(parts) == 2 {
				hdr := r.Header.Get(strings.TrimSpace(parts[0]))
				if !strings.Contains(hdr, strings.TrimSpace(parts[1])) {
					continue
				}
			}
		}
		return p, true
	}
	return Patch{}, false
}

// ListPatches returns all patches.
func (e *Engine) ListPatches() []Patch {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]Patch, len(e.patches))
	copy(result, e.patches)
	return result
}

// AddPatch adds a new virtual patch.
func (e *Engine) AddPatch(p Patch) error {
	if p.PathPattern != "" {
		compiled, err := regexp.Compile(p.PathPattern)
		if err != nil {
			return err
		}
		p.compiledPath = compiled
	}
	if p.BodyPattern != "" {
		compiled, err := regexp.Compile(p.BodyPattern)
		if err != nil {
			return err
		}
		p.compiledBody = compiled
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	p.Enabled = true

	e.mu.Lock()
	e.patches = append(e.patches, p)
	e.mu.Unlock()

	return e.saveToFile()
}

// RemovePatch removes a virtual patch by ID.
func (e *Engine) RemovePatch(id string) bool {
	e.mu.Lock()
	found := false
	for i, p := range e.patches {
		if p.ID == id {
			e.patches = append(e.patches[:i], e.patches[i+1:]...)
			found = true
			break
		}
	}
	e.mu.Unlock()

	if found {
		e.saveToFile()
	}
	return found
}

// GetStats returns virtual patching stats.
func (e *Engine) GetStats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	active := 0
	now := time.Now()
	for _, p := range e.patches {
		if p.Enabled && (p.ExpiresAt.IsZero() || p.ExpiresAt.After(now)) {
			active++
		}
	}
	return map[string]any{
		"total_patches":  len(e.patches),
		"active_patches": active,
		"blocked":        e.blocked,
		"logged":         e.logged,
	}
}

func (e *Engine) loadFromFile() {
	if e.filePath == "" {
		return
	}
	data, err := os.ReadFile(e.filePath)
	if err != nil {
		return
	}
	var patches []Patch
	if err := json.Unmarshal(data, &patches); err != nil {
		return
	}
	for i := range patches {
		if patches[i].PathPattern != "" {
			patches[i].compiledPath, _ = regexp.Compile(patches[i].PathPattern)
		}
		if patches[i].BodyPattern != "" {
			patches[i].compiledBody, _ = regexp.Compile(patches[i].BodyPattern)
		}
	}
	e.mu.Lock()
	e.patches = patches
	e.mu.Unlock()
}

func (e *Engine) saveToFile() error {
	if e.filePath == "" {
		return nil
	}
	e.mu.RLock()
	data, err := json.MarshalIndent(e.patches, "", "  ")
	e.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(e.filePath, data, 0644)
}
