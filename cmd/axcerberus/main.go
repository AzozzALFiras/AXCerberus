// Cerberus — AevonX WAF Engine
//
// Usage:
//
//	axcerberus [-config PATH] [-version] [-check-config]
//	axcerberus exec <action> [args...]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"axcerberus/internal/alert"
	"axcerberus/internal/anomaly"
	"axcerberus/internal/apisec"
	"axcerberus/internal/bot"
	"axcerberus/internal/challenge"
	"axcerberus/internal/cli"
	"axcerberus/internal/compliance"
	"axcerberus/internal/config"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/dlp"
	"axcerberus/internal/geoip"
	"axcerberus/internal/headers"
	"axcerberus/internal/honeypot"
	"axcerberus/internal/logger"
	"axcerberus/internal/proxy"
	"axcerberus/internal/ratelimit"
	"axcerberus/internal/ruledsl"
	"axcerberus/internal/session"
	"axcerberus/internal/ssrf"
	"axcerberus/internal/stats"
	"axcerberus/internal/threatfeed"
	"axcerberus/internal/vpatch"
)

var (
	Version = "dev"
	Commit  = "none"
	BuildAt = "unknown"
)

func main() {
	// CLI exec mode
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		os.Exit(cli.RunExec(os.Args[2:]))
	}

	flags := parseFlags()

	if flags.version {
		fmt.Printf("axcerberus %s (commit %s, built %s)\n", Version, Commit, BuildAt)
		os.Exit(0)
	}

	cfg, err := config.Load(flags.configPath)
	if err != nil {
		log.Fatalf("fatal: load config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("fatal: invalid config: %v", err)
	}

	if flags.checkConfig {
		fmt.Println("config OK")
		os.Exit(0)
	}

	logs, err := logger.New(cfg.AccessLogFile, cfg.ErrorLogFile, cfg.WarningLogFile, cfg.SecurityLogFile)
	if err != nil {
		log.Fatalf("fatal: open log files: %v", err)
	}

	// GeoIP — auto-download free DB-IP Lite database if missing
	var geoDB *geoip.DB
	if cfg.GeoIPDBPath != "" {
		if err := geoip.EnsureDB(cfg.GeoIPDBPath); err != nil {
			logs.Warning.Warn("geoip_auto_download_failed", "error", err.Error())
		}
		geoDB, err = geoip.Open(cfg.GeoIPDBPath)
		if err != nil {
			logs.Warning.Warn("geoip_disabled", "reason", err.Error())
		} else {
			logs.Access.Info("geoip_loaded", "path", cfg.GeoIPDBPath)
		}
	}
	if geoDB != nil {
		defer geoDB.Close()
	}

	// Bot detector
	var botDet *bot.Detector
	if cfg.BotDetectionEnabled {
		botDet = bot.NewDetector()
		logs.Access.Info("bot_detection_enabled")
	}

	// Stats engine
	statsEng := stats.New()
	logs.Access.Info("stats_engine_started")

	// IP Guard
	ipGuard := proxy.NewIPGuard(cfg.IPMaxConcurrentReqs, cfg.IPBlockDurationSecs, cfg.AutoBlockEscalation)
	if cfg.IPAllowlistFile != "" {
		if err := ipGuard.LoadAllowlist(cfg.IPAllowlistFile); err != nil {
			logs.Warning.Warn("ip_allowlist_load_error", "error", err)
		}
	}
	if cfg.IPBlocklistFile != "" {
		if err := ipGuard.LoadBlocklist(cfg.IPBlocklistFile); err != nil {
			logs.Warning.Warn("ip_blocklist_load_error", "error", err)
		}
	}

	// Rate limiter
	var rateLimiter *ratelimit.Limiter
	if cfg.RateLimitEnabled {
		rateLimiter = ratelimit.New(cfg.GlobalRateLimit, cfg.LoginRateLimit, cfg.APIRateLimit,
			cfg.ThrottleMode, cfg.SplitLoginPaths())
		logs.Access.Info("rate_limiter_enabled")
	}

	// Honeypot
	var honeypotEng *honeypot.Engine
	if cfg.HoneypotEnabled {
		honeypotEng = honeypot.New(cfg.SplitHoneypotPaths(), cfg.HoneypotAutoBlock)
		honeypotEng.OnBlock = func(ip string) {
			ipGuard.AddBlock(ip, 3600, "honeypot")
			statsEng.RecordHoneypotHit()
			logs.Security.Warn("honeypot_block", "ip", ip)
		}
		logs.Access.Info("honeypot_enabled", "traps", cfg.HoneypotPaths)
	}

	// DDoS shield
	var ddosShield *ddos.Shield
	if cfg.DDoSEnabled {
		ddosShield = ddos.New(true, cfg.DDoSAutoMitigate, cfg.DDoSSpikeMultiplier, cfg.MaxConnsPerIP)
		logs.Access.Info("ddos_shield_enabled")
	}

	// Credential protection
	var credDet *credential.Detector
	if cfg.CredentialEnabled {
		credDet = credential.New(cfg.SplitLoginPaths(), cfg.MaxLoginAttemptsPerIP, cfg.MaxLoginAttemptsPerUser)
		credDet.OnBlock = func(ip, reason string) {
			ipGuard.AddBlock(ip, 3600, reason)
			statsEng.RecordCredentialAttack()
			logs.Security.Warn("credential_attack_blocked", "ip", ip, "reason", reason)
		}
		logs.Access.Info("credential_protection_enabled")
	}

	// SSRF detector
	var ssrfDet *ssrf.Detector
	if cfg.SSRFEnabled {
		ssrfDet = ssrf.New(true)
		logs.Access.Info("ssrf_detection_enabled")
	}

	// Threat intelligence feeds
	var threatMgr *threatfeed.Manager
	if cfg.ThreatFeedEnabled {
		threatMgr = threatfeed.New(threatfeed.Config{
			Enabled:  true,
			Interval: time.Duration(cfg.ThreatFeedInterval) * time.Second,
		})
		threatMgr.Start()
		logs.Access.Info("threat_feed_enabled", "interval", cfg.ThreatFeedInterval)
	}

	// Challenge system
	var challengeSys *challenge.System
	if cfg.ChallengeEnabled {
		challengeSys = challenge.New(challenge.Config{
			Enabled:   true,
			Duration:  time.Duration(cfg.ChallengeDuration) * time.Second,
			Threshold: cfg.ChallengeThreshold,
		})
		logs.Access.Info("challenge_system_enabled", "duration", cfg.ChallengeDuration, "threshold", cfg.ChallengeThreshold)
	}

	// API security
	var apiSecGuard *apisec.Guard
	if cfg.APISecEnabled {
		apiSecGuard = apisec.New(apisec.Config{
			Enabled:            true,
			MaxBodySize:        cfg.APISecMaxBodySize,
			EnforceContentType: cfg.APISecEnforceContentType,
			GraphQLEnabled:     cfg.APISecGraphQLEnabled,
			GraphQLMaxDepth:    cfg.APISecGraphQLMaxDepth,
			APIPrefix:          cfg.APISecPrefix,
		})
		logs.Access.Info("apisec_enabled", "prefix", cfg.APISecPrefix)
	}

	// Security headers
	var headerHardener *headers.Hardener
	if cfg.SecurityHeadersEnabled {
		headerHardener = headers.New(headers.Config{
			Enabled:       true,
			XFrameOptions: cfg.XFrameOptions,
			CSPPolicy:     cfg.CSPPolicy,
			HSTS:          cfg.ListenTLS != "",
		})
		logs.Access.Info("security_headers_enabled")
	}

	// Alert dispatcher
	alertDisp := alert.New(cfg.AlertsEnabled, cfg.AlertWebhookURL, cfg.AlertMaxPerHour, cfg.AlertSeverityThreshold)

	// DLP scanner
	var dlpScanner *dlp.Scanner
	if cfg.DLPEnabled {
		dlpScanner = dlp.NewScanner(cfg.DLPMode, cfg.DLPCreditCards, cfg.DLPAPIKeys, cfg.DLPStackTraces)
		dlpScanner.OnDetect = func(ev dlp.Event) {
			statsEng.RecordDLPEvent()
			alertDisp.Dispatch(alert.Alert{
				Type:     alert.EventDLPDetection,
				Severity: alert.SevHigh,
				Message:  "DLP detected " + string(ev.Type) + " in " + ev.URI,
			})
			logs.Security.Warn("dlp_detection", "type", string(ev.Type), "uri", ev.URI, "ip", ev.IP, "matches", ev.Matches)
		}
		logs.Access.Info("dlp_scanner_enabled", "mode", cfg.DLPMode)
	}

	// Virtual patching
	var vpatchEng *vpatch.Engine
	if cfg.VPatchEnabled {
		vpatchEng = vpatch.New(cfg.VPatchFile)
		logs.Access.Info("vpatch_enabled", "file", cfg.VPatchFile)
	}

	// Anomaly detection
	var anomalyDet *anomaly.Detector
	if cfg.AnomalyEnabled {
		anomalyDet = anomaly.New(anomaly.Config{
			Enabled:         true,
			WindowMinutes:   cfg.AnomalyWindowMinutes,
			DeviationFactor: cfg.AnomalyDeviationFactor,
			MinSamples:      cfg.AnomalyMinSamples,
		})
		logs.Access.Info("anomaly_detection_enabled")
	}

	// Session tracking
	var sessionTracker *session.Tracker
	if cfg.SessionEnabled {
		sessionTracker = session.New(session.Config{
			Enabled:       true,
			CookieName:    cfg.SessionCookieName,
			MaxPerSession: cfg.SessionMaxPerMinute,
			ATOEnabled:    cfg.SessionATOEnabled,
		})
		logs.Access.Info("session_tracking_enabled")
	}

	// Custom rule DSL
	var ruleDSLEng *ruledsl.Engine
	if cfg.CustomRulesEnabled {
		ruleDSLEng = ruledsl.New()
		logs.Access.Info("custom_rules_enabled")
	}

	// Build deps
	deps := &proxy.Deps{
		Config:      cfg,
		Logger:      logs,
		Stats:       statsEng,
		GeoIP:       geoDB,
		Bot:         botDet,
		IPGuard:     ipGuard,
		RateLimiter: rateLimiter,
		Honeypot:    honeypotEng,
		DDoS:        ddosShield,
		Credential:  credDet,
		Alert:       alertDisp,
		DLP:         dlpScanner,
		SSRF:        ssrfDet,
		Challenge:   challengeSys,
		ThreatFeed:  threatMgr,
		Headers:     headerHardener,
		APISec:      apiSecGuard,
		VPatch:      vpatchEng,
		Anomaly:     anomalyDet,
		Session:     sessionTracker,
		RuleDSL:     ruleDSLEng,
	}

	// Create server
	srv, err := proxy.New(deps)
	if err != nil {
		log.Fatalf("fatal: create server: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Stats API server
	if cfg.StatsAPIEnabled && cfg.StatsAPIListen != "" {
		apiSrv := stats.NewAPIServer(statsEng, cfg.StatsAPIListen)
		apiSrv.SetModules(honeypotEng, ddosShield, credDet)
		apiSrv.SetAlerts(alertDisp)
		apiSrv.SetThreatFeed(threatMgr)
		apiSrv.SetAnomaly(anomalyDet)
		apiSrv.SetSession(sessionTracker)
		apiSrv.SetRuleDSL(ruleDSLEng)
		wafState := &compliance.WAFState{
			WAFEnabled: cfg.WAFEnabled, SSRFEnabled: cfg.SSRFEnabled,
			DLPEnabled: cfg.DLPEnabled, BotEnabled: cfg.BotDetectionEnabled,
			RateLimitEnabled: cfg.RateLimitEnabled, DDoSEnabled: cfg.DDoSEnabled,
			CredentialEnabled: cfg.CredentialEnabled, GeoIPEnabled: geoDB != nil,
			HoneypotEnabled: cfg.HoneypotEnabled, ChallengeEnabled: cfg.ChallengeEnabled,
			ThreatFeedEnabled: cfg.ThreatFeedEnabled, HeadersEnabled: cfg.SecurityHeadersEnabled,
			APISecEnabled: cfg.APISecEnabled, TLSEnabled: cfg.ListenTLS != "",
			LoggingEnabled: true, AlertsEnabled: cfg.AlertsEnabled,
		}
		apiSrv.SetWAFState(wafState)
		go func() {
			logs.Access.Info("stats_api_starting", "addr", cfg.StatsAPIListen)
			if err := apiSrv.Serve(ctx); err != nil {
				logs.Error.Error("stats_api_error", "error", err)
			}
		}()
	}

	// SIGHUP reload
	go watchReload(flags.configPath, srv, logs)

	if err := srv.Serve(ctx); err != nil {
		log.Fatalf("fatal: server exited: %v", err)
	}
}

func watchReload(configPath string, srv *proxy.Server, logs *logger.Logs) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	for range ch {
		newCfg, err := config.Load(configPath)
		if err != nil {
			logs.Error.Error("reload_config_error", "error", err)
			continue
		}
		if err := newCfg.Validate(); err != nil {
			logs.Error.Error("reload_config_invalid", "error", err)
			continue
		}
		if err := srv.Reload(newCfg); err != nil {
			logs.Error.Error("reload_server_error", "error", err)
		}
	}
}

type flags struct {
	configPath  string
	version     bool
	checkConfig bool
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.configPath, "config", config.DefaultPath, "path to config.avx file")
	flag.BoolVar(&f.version, "version", false, "print version and exit")
	flag.BoolVar(&f.checkConfig, "check-config", false, "validate config and exit")
	flag.Parse()
	return f
}
