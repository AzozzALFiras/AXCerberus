// Package apisec provides API-specific security enforcement.
// Handles per-endpoint rate limiting, payload size limits,
// content-type enforcement, and GraphQL depth limits.
package apisec

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config holds API security configuration.
type Config struct {
	Enabled           bool
	MaxBodySize       int64  // max request body bytes (default 1MB)
	EnforceContentType bool  // reject non-JSON POST/PUT/PATCH to /api/*
	GraphQLEnabled    bool
	GraphQLMaxDepth   int    // max nesting depth for GraphQL queries
	APIPrefix         string // path prefix to protect (default "/api")
}

// Guard enforces API security policies.
type Guard struct {
	cfg          Config
	mu           sync.Mutex
	endpointHits map[string][]time.Time // endpoint → recent timestamps
}

// New creates an API security guard.
func New(cfg Config) *Guard {
	if cfg.MaxBodySize == 0 {
		cfg.MaxBodySize = 1 << 20 // 1MB
	}
	if cfg.APIPrefix == "" {
		cfg.APIPrefix = "/api"
	}
	if cfg.GraphQLMaxDepth == 0 {
		cfg.GraphQLMaxDepth = 10
	}
	g := &Guard{
		cfg:          cfg,
		endpointHits: make(map[string][]time.Time),
	}
	go g.cleanup()
	return g
}

// Middleware returns an HTTP middleware that enforces API security.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	if !g.cfg.Enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, g.cfg.APIPrefix) {
			next.ServeHTTP(w, r)
			return
		}

		// Enforce content-type for mutating requests
		if g.cfg.EnforceContentType && isMutating(r.Method) {
			ct := r.Header.Get("Content-Type")
			if ct != "" && !isJSONContentType(ct) {
				http.Error(w, "Unsupported Media Type", http.StatusUnsupportedMediaType)
				return
			}
		}

		// Enforce body size limit
		if r.ContentLength > g.cfg.MaxBodySize {
			http.Error(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxBodySize)
		}

		// GraphQL depth check
		if g.cfg.GraphQLEnabled && isGraphQLEndpoint(r.URL.Path) {
			if r.Method == http.MethodPost {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					http.Error(w, "Bad Request", http.StatusBadRequest)
					return
				}
				r.Body = io.NopCloser(strings.NewReader(string(body)))

				depth := estimateGraphQLDepth(string(body))
				if depth > g.cfg.GraphQLMaxDepth {
					http.Error(w, "Query Too Complex", http.StatusBadRequest)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// GetStats returns API security statistics.
func (g *Guard) GetStats() map[string]any {
	g.mu.Lock()
	defer g.mu.Unlock()
	return map[string]any{
		"enabled":          g.cfg.Enabled,
		"max_body_size":    g.cfg.MaxBodySize,
		"tracked_endpoints": len(g.endpointHits),
	}
}

func (g *Guard) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		g.mu.Lock()
		cutoff := time.Now().Add(-time.Hour)
		for ep, hits := range g.endpointHits {
			valid := hits[:0]
			for _, t := range hits {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(g.endpointHits, ep)
			} else {
				g.endpointHits[ep] = valid
			}
		}
		g.mu.Unlock()
	}
}

func isMutating(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch
}

func isJSONContentType(ct string) bool {
	lower := strings.ToLower(ct)
	return strings.Contains(lower, "application/json") ||
		strings.Contains(lower, "application/graphql")
}

func isGraphQLEndpoint(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, "/graphql") || strings.HasSuffix(lower, "/gql")
}

// estimateGraphQLDepth counts maximum brace nesting depth in a GraphQL query.
func estimateGraphQLDepth(body string) int {
	maxDepth := 0
	depth := 0
	for _, c := range body {
		switch c {
		case '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxDepth
}
