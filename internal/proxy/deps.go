// Package proxy implements the reverse-proxy layer.
package proxy

import (
	"axcerberus/internal/alert"
	"axcerberus/internal/anomaly"
	"axcerberus/internal/apisec"
	"axcerberus/internal/bot"
	"axcerberus/internal/challenge"
	"axcerberus/internal/config"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/dlp"
	"axcerberus/internal/geoip"
	"axcerberus/internal/headers"
	"axcerberus/internal/honeypot"
	"axcerberus/internal/logger"
	"axcerberus/internal/ratelimit"
	"axcerberus/internal/ruledsl"
	"axcerberus/internal/session"
	"axcerberus/internal/ssrf"
	"axcerberus/internal/stats"
	"axcerberus/internal/threatfeed"
	"axcerberus/internal/vpatch"
)

// Deps aggregates all module dependencies injected into the proxy server.
type Deps struct {
	Config      *config.Config
	Logger      *logger.Logs
	Stats       *stats.Engine
	GeoIP       *geoip.DB
	Bot         *bot.Detector
	IPGuard     *IPGuard
	RateLimiter *ratelimit.Limiter
	Honeypot    *honeypot.Engine
	DDoS        *ddos.Shield
	Credential  *credential.Detector
	Alert       *alert.Dispatcher
	DLP         *dlp.Scanner
	SSRF        *ssrf.Detector
	Challenge   *challenge.System
	ThreatFeed  *threatfeed.Manager
	Headers     *headers.Hardener
	APISec      *apisec.Guard
	VPatch      *vpatch.Engine
	Anomaly     *anomaly.Detector
	Session     *session.Tracker
	RuleDSL     *ruledsl.Engine
}
