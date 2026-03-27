// Package compliance generates PCI-DSS and security compliance reports.
package compliance

import (
	"time"
)

// CheckStatus represents whether a compliance check passed.
type CheckStatus string

const (
	StatusPass CheckStatus = "pass"
	StatusFail CheckStatus = "fail"
	StatusWarn CheckStatus = "warn"
)

// Check represents a single compliance check.
type Check struct {
	ID          string      `json:"id"`
	Category    string      `json:"category"`
	Requirement string      `json:"requirement"`
	Description string      `json:"description"`
	Status      CheckStatus `json:"status"`
	Details     string      `json:"details,omitempty"`
}

// Report represents a full compliance report.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Framework   string    `json:"framework"`
	Score       int       `json:"score"`       // percentage
	TotalChecks int       `json:"total_checks"`
	Passed      int       `json:"passed"`
	Failed      int       `json:"failed"`
	Warnings    int       `json:"warnings"`
	Checks      []Check   `json:"checks"`
}

// WAFState captures the current WAF configuration for compliance checks.
type WAFState struct {
	WAFEnabled       bool
	SSRFEnabled      bool
	DLPEnabled       bool
	BotEnabled       bool
	RateLimitEnabled bool
	DDoSEnabled      bool
	CredentialEnabled bool
	GeoIPEnabled     bool
	HoneypotEnabled  bool
	ChallengeEnabled bool
	ThreatFeedEnabled bool
	HeadersEnabled   bool
	APISecEnabled    bool
	TLSEnabled       bool
	LoggingEnabled   bool
	AlertsEnabled    bool
}

// GeneratePCIDSS generates a PCI-DSS compliance report.
func GeneratePCIDSS(state WAFState) Report {
	checks := make([]Check, 0, 20)

	// PCI-DSS Requirement 6.6: WAF protection
	checks = append(checks, check("PCI-6.6.1", "6.6", "WAF Protection",
		"Web Application Firewall must be active", state.WAFEnabled))

	checks = append(checks, check("PCI-6.6.2", "6.6", "WAF Protection",
		"SSRF prevention must be enabled", state.SSRFEnabled))

	checks = append(checks, check("PCI-6.6.3", "6.6", "WAF Protection",
		"Bot detection must be enabled", state.BotEnabled))

	// PCI-DSS Requirement 6.5: Secure coding
	checks = append(checks, check("PCI-6.5.1", "6.5", "Secure Coding",
		"DLP must be enabled to prevent data leaks", state.DLPEnabled))

	// PCI-DSS Requirement 8: Authentication
	checks = append(checks, check("PCI-8.1.1", "8.1", "Authentication",
		"Credential stuffing protection must be active", state.CredentialEnabled))

	checks = append(checks, check("PCI-8.1.2", "8.1", "Authentication",
		"Rate limiting must be enabled for login paths", state.RateLimitEnabled))

	// PCI-DSS Requirement 10: Logging
	checks = append(checks, check("PCI-10.1", "10.1", "Logging",
		"Access logging must be enabled", state.LoggingEnabled))

	checks = append(checks, check("PCI-10.6.1", "10.6", "Log Monitoring",
		"Security alerts must be enabled", state.AlertsEnabled))

	// PCI-DSS Requirement 11: Security Testing
	checks = append(checks, check("PCI-11.4.1", "11.4", "Intrusion Detection",
		"DDoS protection must be active", state.DDoSEnabled))

	checks = append(checks, check("PCI-11.4.2", "11.4", "Intrusion Detection",
		"Honeypot traps should be enabled", state.HoneypotEnabled))

	// Additional security best practices
	checks = append(checks, check("SEC-1", "Security", "Headers",
		"Security response headers should be enabled", state.HeadersEnabled))

	checks = append(checks, check("SEC-2", "Security", "TLS",
		"TLS encryption should be configured", state.TLSEnabled))

	checks = append(checks, check("SEC-3", "Security", "GeoIP",
		"GeoIP blocking should be available", state.GeoIPEnabled))

	checks = append(checks, check("SEC-4", "Security", "Challenge",
		"Challenge system should be available", state.ChallengeEnabled))

	checks = append(checks, check("SEC-5", "Security", "Threat Intel",
		"Threat intelligence feeds should be enabled", state.ThreatFeedEnabled))

	checks = append(checks, check("SEC-6", "Security", "API",
		"API security module should be enabled", state.APISecEnabled))

	// Calculate score
	passed := 0
	failed := 0
	warnings := 0
	for _, c := range checks {
		switch c.Status {
		case StatusPass:
			passed++
		case StatusFail:
			failed++
		case StatusWarn:
			warnings++
		}
	}

	score := 0
	if len(checks) > 0 {
		score = (passed * 100) / len(checks)
	}

	return Report{
		GeneratedAt: time.Now(),
		Framework:   "PCI-DSS v4.0 + Security Best Practices",
		Score:       score,
		TotalChecks: len(checks),
		Passed:      passed,
		Failed:      failed,
		Warnings:    warnings,
		Checks:      checks,
	}
}

func check(id, category, requirement, desc string, enabled bool) Check {
	status := StatusFail
	details := "Not enabled"
	if enabled {
		status = StatusPass
		details = "Enabled and active"
	}
	return Check{
		ID:          id,
		Category:    category,
		Requirement: requirement,
		Description: desc,
		Status:      status,
		Details:     details,
	}
}
