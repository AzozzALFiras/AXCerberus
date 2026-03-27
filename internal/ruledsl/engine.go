// Package ruledsl provides a simple DSL for custom WAF rules.
// Syntax:
//
//	WHEN <conditions> THEN <action>
//
// Conditions:
//
//	path.startsWith("/api")
//	path.contains(".php")
//	method == "POST"
//	header["X-Custom"] == "value"
//	body.size > 1048576
//	ip.in("192.168.0.0/16")
//	query.contains("select")
//
// Actions: block, challenge, log, allow
package ruledsl

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// Rule represents a parsed custom rule.
type Rule struct {
	ID         string      `json:"id"`
	Raw        string      `json:"raw"`
	Conditions []Condition `json:"conditions"`
	Action     string      `json:"action"`
	Enabled    bool        `json:"enabled"`
}

// Condition represents a single condition in a rule.
type Condition struct {
	Field    string `json:"field"`    // "path", "method", "header", "body.size", "ip", "query"
	Operator string `json:"operator"` // "startsWith", "contains", "==", ">", "<", "in"
	Value    string `json:"value"`
}

// Engine evaluates custom DSL rules against requests.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule

	matched int64
	blocked int64
}

// New creates a rule DSL engine.
func New() *Engine {
	return &Engine{
		rules: make([]Rule, 0),
	}
}

// AddRule parses and adds a custom rule.
func (e *Engine) AddRule(id, raw string) error {
	rule, err := Parse(raw)
	if err != nil {
		return err
	}
	rule.ID = id
	rule.Raw = raw
	rule.Enabled = true

	e.mu.Lock()
	e.rules = append(e.rules, rule)
	e.mu.Unlock()
	return nil
}

// RemoveRule removes a rule by ID.
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// ListRules returns all rules.
func (e *Engine) ListRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]Rule, len(e.rules))
	copy(result, e.rules)
	return result
}

// Middleware returns an HTTP middleware that evaluates custom rules.
func (e *Engine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if action := e.Evaluate(r); action != "" {
			switch action {
			case "block":
				e.mu.Lock()
				e.blocked++
				e.mu.Unlock()
				http.Error(w, "Forbidden — Custom Rule", http.StatusForbidden)
				return
			case "challenge":
				r.Header.Set("X-Bot-Score", "suspicious")
			case "log":
				r.Header.Set("X-Custom-Rule-Match", "true")
			case "allow":
				r.Header.Set("X-AXCerberus-Allowlisted", "true")
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Evaluate checks all rules against a request and returns the action of the first match.
func (e *Engine) Evaluate(r *http.Request) string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if matchesAll(rule.Conditions, r) {
			e.matched++
			return rule.Action
		}
	}
	return ""
}

// GetStats returns rule engine stats.
func (e *Engine) GetStats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return map[string]any{
		"total_rules": len(e.rules),
		"matched":     e.matched,
		"blocked":     e.blocked,
	}
}

func matchesAll(conditions []Condition, r *http.Request) bool {
	for _, c := range conditions {
		if !matchCondition(c, r) {
			return false
		}
	}
	return true
}

func matchCondition(c Condition, r *http.Request) bool {
	switch c.Field {
	case "path":
		return matchString(r.URL.Path, c.Operator, c.Value)
	case "method":
		return strings.EqualFold(r.Method, c.Value)
	case "query":
		return matchString(r.URL.RawQuery, c.Operator, c.Value)
	case "body.size":
		return matchInt(r.ContentLength, c.Operator, c.Value)
	case "ip":
		ip := extractClientIP(r)
		if c.Operator == "in" {
			return ipInCIDR(ip, c.Value)
		}
		return ip == c.Value
	default:
		// header["X-Something"]
		if strings.HasPrefix(c.Field, "header[") && strings.HasSuffix(c.Field, "]") {
			headerName := c.Field[7 : len(c.Field)-1]
			headerName = strings.Trim(headerName, "\"'")
			return matchString(r.Header.Get(headerName), c.Operator, c.Value)
		}
	}
	return false
}

func matchString(actual, operator, expected string) bool {
	switch operator {
	case "startsWith":
		return strings.HasPrefix(actual, expected)
	case "contains":
		return strings.Contains(actual, expected)
	case "endsWith":
		return strings.HasSuffix(actual, expected)
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	}
	return false
}

func matchInt(actual int64, operator, expected string) bool {
	val, err := strconv.ParseInt(expected, 10, 64)
	if err != nil {
		return false
	}
	switch operator {
	case ">":
		return actual > val
	case "<":
		return actual < val
	case ">=":
		return actual >= val
	case "<=":
		return actual <= val
	case "==":
		return actual == val
	}
	return false
}

func ipInCIDR(ip, cidr string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ip == cidr
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return network.Contains(parsed)
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Real-IP"); xff != "" {
		return strings.TrimSpace(xff)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}
