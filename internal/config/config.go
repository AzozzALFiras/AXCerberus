// Package config loads and validates the plugin configuration from a config.avx file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// DefaultPath is the canonical runtime location of the config file.
const DefaultPath = "/etc/aevonx/plugins/axcerberus/config.avx"

// Config holds all runtime configuration for Cerberus.
type Config struct {
	// ── Network ──────────────────────────────────────────────────
	Listen            string
	ListenTLS         string
	TLSCertFile       string
	TLSKeyFile        string
	Upstream          string
	TrustProxyHeaders bool

	// ── Routing ──────────────────────────────────────────────────
	Domains string // comma-separated allowed domains
	Routes  string // comma-separated path prefixes

	// ── WAF (Coraza) ─────────────────────────────────────────────
	WAFEnabled       bool
	RulesFiles       string
	AnomalyThreshold int

	// ── IP Guard ─────────────────────────────────────────────────
	IPMaxConcurrentReqs    int
	IPBlockDurationSecs    int // seconds; -1 = permanent
	IPAllowlistFile        string
	IPBlocklistFile        string
	AutoBlockEscalation    bool // progressive: 5min → 1hr → 24hr → perm

	// ── URL Lists ────────────────────────────────────────────────
	URLAllowlist string // comma-separated paths to skip WAF
	URLBlocklist string // comma-separated paths to always block

	// ── GeoIP ────────────────────────────────────────────────────
	GeoIPDBPath        string
	GeoBlockCountries  string // comma-separated ISO codes to block
	GeoAllowCountries  string // if set, ONLY these countries allowed
	GeoBlockMode       string // "blocklist" or "allowlist"

	// ── Rate Limiting ────────────────────────────────────────────
	RateLimitEnabled   bool
	GlobalRateLimit    int // req/min per IP
	LoginRateLimit     int // req/min for login endpoints
	APIRateLimit       int // req/min for /api/* paths
	ThrottleMode       bool

	// ── Bot Detection ────────────────────────────────────────────
	BotDetectionEnabled bool

	// ── Honeypot ─────────────────────────────────────────────────
	HoneypotEnabled    bool
	HoneypotPaths      string // comma-separated trap paths
	HoneypotAutoBlock  bool

	// ── DDoS Shield ──────────────────────────────────────────────
	DDoSEnabled        bool
	DDoSAutoMitigate   bool
	DDoSBaselineDays   int
	DDoSSpikeMultiplier float64
	SlowHTTPTimeout    int // seconds
	MaxConnsPerIP      int

	// ── Credential Protection ────────────────────────────────────
	CredentialEnabled         bool
	LoginPaths                string // comma-separated POST paths
	MaxLoginAttemptsPerIP     int    // per hour
	MaxLoginAttemptsPerUser   int    // per hour

	// ── Data Leak Prevention ─────────────────────────────────────
	DLPEnabled     bool
	DLPCreditCards bool
	DLPAPIKeys     bool
	DLPStackTraces bool
	DLPMode        string // "block", "mask", "log"

	// ── SSRF Prevention ──────────────────────────────────────────
	SSRFEnabled bool

	// ── Threat Intelligence ─────────────────────────────────────
	ThreatFeedEnabled  bool
	ThreatFeedInterval int // seconds between feed refreshes

	// ── API Security ────────────────────────────────────────────
	APISecEnabled        bool
	APISecMaxBodySize    int64  // bytes
	APISecEnforceContentType bool
	APISecGraphQLEnabled bool
	APISecGraphQLMaxDepth int
	APISecPrefix         string

	// ── Security Headers ────────────────────────────────────────
	SecurityHeadersEnabled bool
	CSPPolicy              string // Content-Security-Policy value
	XFrameOptions          string // DENY, SAMEORIGIN, or empty

	// ── Challenge System ────────────────────────────────────────
	ChallengeEnabled  bool
	ChallengeDuration int // seconds
	ChallengeThreshold int // bot score threshold

	// ── Virtual Patching ────────────────────────────────────────
	VPatchEnabled bool
	VPatchFile    string // path to vpatches.json

	// ── Anomaly Detection ───────────────────────────────────────
	AnomalyEnabled         bool
	AnomalyWindowMinutes   int
	AnomalyDeviationFactor float64
	AnomalyMinSamples      int

	// ── Session Tracking ────────────────────────────────────────
	SessionEnabled       bool
	SessionCookieName    string
	SessionMaxPerMinute  int
	SessionATOEnabled    bool

	// ── Custom Rules ────────────────────────────────────────────
	CustomRulesEnabled bool
	CustomRulesFile    string // path to custom_rules.json

	// ── Alerts ───────────────────────────────────────────────────
	AlertsEnabled         bool
	AlertWebhookURL       string
	AlertMaxPerHour       int
	AlertSeverityThreshold string // "low", "medium", "high", "critical"

	// ── Stats API ────────────────────────────────────────────────
	StatsAPIListen  string
	StatsAPIEnabled bool

	// ── Timeouts ─────────────────────────────────────────────────
	ReadTimeoutSecs  int
	WriteTimeoutSecs int

	// ── Logging ──────────────────────────────────────────────────
	AccessLogFile   string
	ErrorLogFile    string
	WarningLogFile  string
	SecurityLogFile string
}

// Default returns a Config populated with safe production defaults.
func Default() *Config {
	return &Config{
		Listen:            ":80",
		Upstream:          "http://127.0.0.1:8181",
		TrustProxyHeaders: true,

		WAFEnabled:       true,
		RulesFiles:       "/etc/aevonx/plugins/axcerberus/rules/*.conf",
		AnomalyThreshold: 5,

		IPMaxConcurrentReqs: 50,
		IPBlockDurationSecs: 300,
		IPAllowlistFile:     "/etc/aevonx/plugins/axcerberus/ip_allowlist.avx",
		IPBlocklistFile:     "/etc/aevonx/plugins/axcerberus/ip_blocklist.avx",
		AutoBlockEscalation: true,

		GeoIPDBPath:  "/etc/aevonx/plugins/axcerberus/GeoLite2-Country.mmdb",
		GeoBlockMode: "blocklist",

		RateLimitEnabled: true,
		GlobalRateLimit:  300,
		LoginRateLimit:   10,
		APIRateLimit:     120,

		BotDetectionEnabled: true,

		HoneypotEnabled:   false,
		HoneypotPaths:     "/wp-admin,/phpmyadmin,/.env,/wp-login.php,/xmlrpc.php,/.git/config,/actuator",
		HoneypotAutoBlock: true,

		DDoSEnabled:         true,
		DDoSAutoMitigate:    true,
		DDoSBaselineDays:    7,
		DDoSSpikeMultiplier: 3.0,
		SlowHTTPTimeout:     30,
		MaxConnsPerIP:       100,

		CredentialEnabled:       true,
		LoginPaths:              "/login,/signin,/auth,/api/login,/api/auth,/wp-login.php",
		MaxLoginAttemptsPerIP:   20,
		MaxLoginAttemptsPerUser: 10,

		DLPEnabled:     true,
		DLPCreditCards: true,
		DLPAPIKeys:     true,
		DLPStackTraces: true,
		DLPMode:        "log",

		SSRFEnabled: true,

		APISecEnabled:           false,
		APISecMaxBodySize:       1 << 20, // 1MB
		APISecEnforceContentType: true,
		APISecGraphQLEnabled:    false,
		APISecGraphQLMaxDepth:   10,
		APISecPrefix:            "/api",

		ThreatFeedEnabled:  false,
		ThreatFeedInterval: 3600,

		SecurityHeadersEnabled: true,
		XFrameOptions:          "DENY",

		VPatchEnabled: false,
		VPatchFile:    "/etc/aevonx/plugins/axcerberus/vpatches.json",

		AnomalyEnabled:         false,
		AnomalyWindowMinutes:   60,
		AnomalyDeviationFactor: 3.0,
		AnomalyMinSamples:      100,

		SessionEnabled:      false,
		SessionMaxPerMinute: 120,
		SessionATOEnabled:   true,

		CustomRulesEnabled: false,
		CustomRulesFile:    "/etc/aevonx/plugins/axcerberus/custom_rules.json",

		ChallengeEnabled:   false,
		ChallengeDuration:  3600,
		ChallengeThreshold: 60,

		AlertsEnabled:          false,
		AlertMaxPerHour:        10,
		AlertSeverityThreshold: "high",

		StatsAPIListen:  "127.0.0.1:9443",
		StatsAPIEnabled: true,

		ReadTimeoutSecs:  30,
		WriteTimeoutSecs: 30,

		AccessLogFile:   "/var/log/aevonx/plugins/axcerberus/waf.access.log",
		ErrorLogFile:    "/var/log/aevonx/plugins/axcerberus/waf.error.log",
		WarningLogFile:  "/var/log/aevonx/plugins/axcerberus/waf.warning.log",
		SecurityLogFile: "/var/log/aevonx/plugins/axcerberus/waf.security.log",
	}
}

// Load reads a config.avx file and merges its values onto the defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}

	cfg := Default()

	if schema, ok := raw["config_schema"]; ok {
		if err := applySchema(cfg, schema); err != nil {
			return nil, fmt.Errorf("config: apply schema: %w", err)
		}
		return cfg, nil
	}

	applyFlat(cfg, raw)
	return cfg, nil
}

// Validate checks that the required fields have sensible values.
func (c *Config) Validate() error {
	if c.Listen == "" {
		return fmt.Errorf("config: listen address is empty")
	}
	if c.Upstream == "" {
		return fmt.Errorf("config: upstream URL is empty")
	}
	if c.ReadTimeoutSecs <= 0 {
		return fmt.Errorf("config: read_timeout_seconds must be > 0")
	}
	if c.WriteTimeoutSecs <= 0 {
		return fmt.Errorf("config: write_timeout_seconds must be > 0")
	}
	if c.DLPMode != "" && c.DLPMode != "block" && c.DLPMode != "mask" && c.DLPMode != "log" {
		return fmt.Errorf("config: dlp_mode must be block, mask, or log")
	}
	if c.GeoBlockMode != "" && c.GeoBlockMode != "blocklist" && c.GeoBlockMode != "allowlist" {
		return fmt.Errorf("config: geo_block_mode must be blocklist or allowlist")
	}
	return nil
}

// SplitGeoBlockCountries returns the blocked country codes as a slice.
func (c *Config) SplitGeoBlockCountries() []string {
	return splitTrim(c.GeoBlockCountries)
}

// SplitGeoAllowCountries returns the allowed country codes as a slice.
func (c *Config) SplitGeoAllowCountries() []string {
	return splitTrim(c.GeoAllowCountries)
}

// SplitLoginPaths returns login paths as a slice.
func (c *Config) SplitLoginPaths() []string {
	return splitTrim(c.LoginPaths)
}

// SplitHoneypotPaths returns honeypot trap paths as a slice.
func (c *Config) SplitHoneypotPaths() []string {
	return splitTrim(c.HoneypotPaths)
}

func splitTrim(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// schema/flat parsing
// ---------------------------------------------------------------------------

func applySchema(cfg *Config, schema any) error {
	sections, ok := schema.([]any)
	if !ok {
		return fmt.Errorf("config_schema must be an array")
	}
	for _, sec := range sections {
		section, ok := sec.(map[string]any)
		if !ok {
			continue
		}
		fields, ok := section["fields"].([]any)
		if !ok {
			continue
		}
		for _, f := range fields {
			field, ok := f.(map[string]any)
			if !ok {
				continue
			}
			key, _ := field["key"].(string)
			val := field["value"]
			applyField(cfg, key, val)
		}
	}
	return nil
}

func applyFlat(cfg *Config, m map[string]any) {
	for k, v := range m {
		applyField(cfg, k, v)
	}
}

func applyField(cfg *Config, key string, val any) {
	switch key {
	// Network
	case "listen":
		cfg.Listen = toString(val)
	case "listen_tls":
		cfg.ListenTLS = toString(val)
	case "tls_cert_file":
		cfg.TLSCertFile = toString(val)
	case "tls_key_file":
		cfg.TLSKeyFile = toString(val)
	case "upstream":
		cfg.Upstream = toString(val)
	case "trust_proxy_headers":
		cfg.TrustProxyHeaders = toBool(val)

	// Routing
	case "domains":
		cfg.Domains = toString(val)
	case "routes":
		cfg.Routes = toString(val)

	// WAF
	case "waf_enabled":
		cfg.WAFEnabled = toBool(val)
	case "rules_files":
		cfg.RulesFiles = toString(val)
	case "anomaly_threshold":
		cfg.AnomalyThreshold = toInt(val)

	// IP Guard
	case "ip_max_concurrent_requests":
		cfg.IPMaxConcurrentReqs = toInt(val)
	case "ip_block_duration":
		cfg.IPBlockDurationSecs = toInt(val)
	case "ip_allowlist_file":
		cfg.IPAllowlistFile = toString(val)
	case "ip_blocklist_file":
		cfg.IPBlocklistFile = toString(val)
	case "auto_block_escalation":
		cfg.AutoBlockEscalation = toBool(val)

	// URL Lists
	case "url_allowlist":
		cfg.URLAllowlist = toString(val)
	case "url_blocklist":
		cfg.URLBlocklist = toString(val)

	// GeoIP
	case "geoip_db_path":
		cfg.GeoIPDBPath = toString(val)
	case "geo_block_countries":
		cfg.GeoBlockCountries = toString(val)
	case "geo_allow_countries":
		cfg.GeoAllowCountries = toString(val)
	case "geo_block_mode":
		cfg.GeoBlockMode = toString(val)

	// Rate Limiting
	case "rate_limit_enabled":
		cfg.RateLimitEnabled = toBool(val)
	case "global_rate_limit":
		cfg.GlobalRateLimit = toInt(val)
	case "login_rate_limit":
		cfg.LoginRateLimit = toInt(val)
	case "api_rate_limit":
		cfg.APIRateLimit = toInt(val)
	case "throttle_mode":
		cfg.ThrottleMode = toBool(val)

	// Bot
	case "bot_detection_enabled":
		cfg.BotDetectionEnabled = toBool(val)

	// Honeypot
	case "honeypot_enabled":
		cfg.HoneypotEnabled = toBool(val)
	case "honeypot_paths":
		cfg.HoneypotPaths = toString(val)
	case "honeypot_auto_block":
		cfg.HoneypotAutoBlock = toBool(val)

	// DDoS
	case "ddos_enabled":
		cfg.DDoSEnabled = toBool(val)
	case "ddos_auto_mitigate":
		cfg.DDoSAutoMitigate = toBool(val)
	case "ddos_baseline_days":
		cfg.DDoSBaselineDays = toInt(val)
	case "ddos_spike_multiplier":
		cfg.DDoSSpikeMultiplier = toFloat(val)
	case "slowhttp_timeout":
		cfg.SlowHTTPTimeout = toInt(val)
	case "max_connections_per_ip":
		cfg.MaxConnsPerIP = toInt(val)

	// Credential
	case "credential_protection_enabled":
		cfg.CredentialEnabled = toBool(val)
	case "login_paths":
		cfg.LoginPaths = toString(val)
	case "max_login_attempts_per_ip":
		cfg.MaxLoginAttemptsPerIP = toInt(val)
	case "max_login_attempts_per_username":
		cfg.MaxLoginAttemptsPerUser = toInt(val)

	// DLP
	case "dlp_enabled":
		cfg.DLPEnabled = toBool(val)
	case "dlp_credit_cards":
		cfg.DLPCreditCards = toBool(val)
	case "dlp_api_keys":
		cfg.DLPAPIKeys = toBool(val)
	case "dlp_stack_traces":
		cfg.DLPStackTraces = toBool(val)
	case "dlp_mode":
		cfg.DLPMode = toString(val)

	// SSRF
	case "ssrf_enabled":
		cfg.SSRFEnabled = toBool(val)

	// Challenge
	case "challenge_enabled":
		cfg.ChallengeEnabled = toBool(val)
	case "challenge_duration":
		cfg.ChallengeDuration = toInt(val)
	case "challenge_threshold":
		cfg.ChallengeThreshold = toInt(val)

	// API Security
	case "apisec_enabled":
		cfg.APISecEnabled = toBool(val)
	case "apisec_max_body_size":
		cfg.APISecMaxBodySize = int64(toInt(val))
	case "apisec_enforce_content_type":
		cfg.APISecEnforceContentType = toBool(val)
	case "apisec_graphql_enabled":
		cfg.APISecGraphQLEnabled = toBool(val)
	case "apisec_graphql_max_depth":
		cfg.APISecGraphQLMaxDepth = toInt(val)
	case "apisec_prefix":
		cfg.APISecPrefix = toString(val)

	// Threat Feed
	case "threat_feed_enabled":
		cfg.ThreatFeedEnabled = toBool(val)
	case "threat_feed_interval":
		cfg.ThreatFeedInterval = toInt(val)

	// Security Headers
	case "security_headers_enabled":
		cfg.SecurityHeadersEnabled = toBool(val)
	case "csp_policy":
		cfg.CSPPolicy = toString(val)
	case "x_frame_options":
		cfg.XFrameOptions = toString(val)

	// Virtual Patching
	case "vpatch_enabled":
		cfg.VPatchEnabled = toBool(val)
	case "vpatch_file":
		cfg.VPatchFile = toString(val)

	// Anomaly Detection
	case "anomaly_enabled":
		cfg.AnomalyEnabled = toBool(val)
	case "anomaly_window_minutes":
		cfg.AnomalyWindowMinutes = toInt(val)
	case "anomaly_deviation_factor":
		cfg.AnomalyDeviationFactor = toFloat(val)
	case "anomaly_min_samples":
		cfg.AnomalyMinSamples = toInt(val)

	// Session Tracking
	case "session_enabled":
		cfg.SessionEnabled = toBool(val)
	case "session_cookie_name":
		cfg.SessionCookieName = toString(val)
	case "session_max_per_minute":
		cfg.SessionMaxPerMinute = toInt(val)
	case "session_ato_enabled":
		cfg.SessionATOEnabled = toBool(val)

	// Custom Rules
	case "custom_rules_enabled":
		cfg.CustomRulesEnabled = toBool(val)
	case "custom_rules_file":
		cfg.CustomRulesFile = toString(val)

	// Alerts
	case "alerts_enabled":
		cfg.AlertsEnabled = toBool(val)
	case "alert_webhook_url":
		cfg.AlertWebhookURL = toString(val)
	case "alert_max_per_hour":
		cfg.AlertMaxPerHour = toInt(val)
	case "alert_severity_threshold":
		cfg.AlertSeverityThreshold = toString(val)

	// Stats
	case "stats_api_listen":
		cfg.StatsAPIListen = toString(val)
	case "stats_api_enabled":
		cfg.StatsAPIEnabled = toBool(val)

	// Timeouts
	case "read_timeout_seconds":
		cfg.ReadTimeoutSecs = toInt(val)
	case "write_timeout_seconds":
		cfg.WriteTimeoutSecs = toInt(val)

	// Logging
	case "access_log_file":
		cfg.AccessLogFile = toString(val)
	case "error_log_file":
		cfg.ErrorLogFile = toString(val)
	case "warning_log_file":
		cfg.WarningLogFile = toString(val)
	case "security_log_file":
		cfg.SecurityLogFile = toString(val)
	}
}

// ---------------------------------------------------------------------------
// type coercions
// ---------------------------------------------------------------------------

func toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func toBool(v any) bool {
	if v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, _ := strconv.ParseBool(t)
		return b
	case float64:
		return t != 0
	}
	return false
}

func toInt(v any) int {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

func toFloat(v any) float64 {
	if v == nil {
		return 0.0
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return 0.0
}
