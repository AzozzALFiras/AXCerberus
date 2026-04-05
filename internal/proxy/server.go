package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"axcerberus/internal/config"
	"axcerberus/internal/geoip"
	axhttp "axcerberus/internal/httputil"
	"axcerberus/internal/pipeline"
	"axcerberus/internal/stats"
	"axcerberus/internal/waf"

	"github.com/google/uuid"
)

// Server is the Cerberus WAF reverse-proxy server.
type Server struct {
	deps    *Deps
	handler atomic.Value
	mu      sync.Mutex
}

// New constructs a Server from the given dependencies.
func New(deps *Deps) (*Server, error) {
	s := &Server{deps: deps}
	if err := s.buildHandler(); err != nil {
		return nil, err
	}
	return s, nil
}

// Serve starts HTTP and optionally HTTPS servers.
func (s *Server) Serve(ctx context.Context) error {
	cfg := s.deps.Config
	httpSrv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      s,
		ReadTimeout:  time.Duration(cfg.ReadTimeoutSecs) * time.Second,
		WriteTimeout: time.Duration(cfg.WriteTimeoutSecs) * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		s.deps.Logger.Access.Info("http_server_starting", "addr", cfg.Listen, "upstream", cfg.Upstream)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()

	var httpsSrv *http.Server
	if cfg.ListenTLS != "" && cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		httpsSrv = &http.Server{
			Addr:         cfg.ListenTLS,
			Handler:      s,
			ReadTimeout:  time.Duration(cfg.ReadTimeoutSecs) * time.Second,
			WriteTimeout: time.Duration(cfg.WriteTimeoutSecs) * time.Second,
		}
		go func() {
			s.deps.Logger.Access.Info("https_server_starting", "addr", cfg.ListenTLS)
			if err := httpsSrv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("https: %w", err)
			}
		}()
	}

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.deps.Logger.Access.Info("servers_shutting_down")
		httpSrv.Shutdown(shutCtx)
		if httpsSrv != nil {
			httpsSrv.Shutdown(shutCtx)
		}
		return nil
	case err := <-errCh:
		return fmt.Errorf("proxy: server: %w", err)
	}
}

// Reload atomically replaces the handler with one built from newCfg.
func (s *Server) Reload(newCfg *config.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deps.Config = newCfg
	if err := s.buildHandler(); err != nil {
		return fmt.Errorf("proxy: reload: %w", err)
	}
	s.deps.Logger.Access.Info("config_reloaded")
	return nil
}

// IPGuardRef returns the IP guard for external management.
func (s *Server) IPGuardRef() *IPGuard {
	return s.deps.IPGuard
}

// ServeHTTP satisfies http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		return
	}

	cfg := s.deps.Config

	if !hostAllowed(r.Host, cfg.Domains) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	if isURLBlocked(r.URL.Path, cfg.URLBlocklist) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// IP guard
	ip, _, blocked, retryAfter := s.deps.IPGuard.Allow(axhttp.RealIP(r))
	if blocked {
		if !retryAfter.IsZero() {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(retryAfter).Seconds())))
		}
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)

		clientIP := axhttp.RealIP(r)
		var cc, cn string
		if s.deps.GeoIP != nil {
			geo := s.deps.GeoIP.Lookup(clientIP)
			cc = geo.CountryCode
			cn = geo.CountryName
		}
		s.deps.Logger.Security.Warn("ip_blocked", "ip", clientIP, "country_code", cc, "country_name", cn)
		if s.deps.Stats != nil {
			s.deps.Stats.RecordRequest(r.Host, true, http.StatusTooManyRequests, 0, 0)
			s.deps.Stats.RecordAttack(clientIP, cn, cc, "Rate Limit", r.URL.Path)
			s.deps.Stats.RecordBlockLog(stats.BlockLogEntry{
				IP:          clientIP,
				Country:     cn,
				CountryCode: cc,
				Method:      r.Method,
				Host:        r.Host,
				Path:        r.URL.Path,
				Rule:        "Rate Limit",
				Reason:      "IP exceeded concurrent request limit",
				Severity:    "high",
				UserAgent:   r.Header.Get("User-Agent"),
			})
		}
		return
	}
	if ip != "" {
		defer s.deps.IPGuard.Release(ip)
	}

	h, _ := s.handler.Load().(http.Handler)
	if h == nil {
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	h.ServeHTTP(w, r)
}

// buildHandler constructs the full middleware chain.
func (s *Server) buildHandler() error {
	cfg := s.deps.Config

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return fmt.Errorf("proxy: invalid upstream %q: %w", cfg.Upstream, err)
	}

	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		s.deps.Logger.Error.Error("upstream_error", "upstream", cfg.Upstream, "error", err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	baseDirector := rp.Director
	rp.Director = func(r *http.Request) {
		baseDirector(r)
		if cfg.TrustProxyHeaders {
			clientIP := axhttp.RealIP(r)
			if prior := r.Header.Get("X-Forwarded-For"); prior != "" {
				r.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				r.Header.Set("X-Forwarded-For", clientIP)
			}
			r.Header.Set("X-Real-IP", clientIP)
		}
	}

	// Build middleware chain using pipeline
	var middlewares []pipeline.Middleware

	// Logging (outermost)
	middlewares = append(middlewares, loggingMiddleware(s.deps))

	// GeoIP blocking
	if s.deps.GeoIP != nil {
		countries := cfg.SplitGeoBlockCountries()
		if cfg.GeoBlockMode == "allowlist" {
			countries = cfg.SplitGeoAllowCountries()
		}
		if len(countries) > 0 {
			blocker := geoip.NewBlocker(s.deps.GeoIP, cfg.GeoBlockMode, countries)
			middlewares = append(middlewares, blocker.Middleware)
		}
	}

	// Threat intelligence feed blocking
	if s.deps.ThreatFeed != nil {
		middlewares = append(middlewares, s.deps.ThreatFeed.Middleware)
	}

	// Bot enforcement (blocks malicious bots before rate limiting)
	if s.deps.Bot != nil {
		middlewares = append(middlewares, s.deps.Bot.Middleware)
	}

	// JS challenge (for suspicious bots tagged by bot enforcement)
	if s.deps.Challenge != nil {
		middlewares = append(middlewares, s.deps.Challenge.Middleware)
	}

	// Rate limiting
	if s.deps.RateLimiter != nil {
		middlewares = append(middlewares, s.deps.RateLimiter.Middleware)
	}

	// Honeypot
	if s.deps.Honeypot != nil {
		middlewares = append(middlewares, s.deps.Honeypot.Middleware)
	}

	// DDoS shield
	if s.deps.DDoS != nil {
		middlewares = append(middlewares, s.deps.DDoS.Middleware)
	}

	// Credential protection
	if s.deps.Credential != nil {
		middlewares = append(middlewares, s.deps.Credential.Middleware)
	}

	// SSRF prevention
	if s.deps.SSRF != nil {
		middlewares = append(middlewares, s.deps.SSRF.Middleware)
	}

	// Session tracking (ATO, impossible travel)
	if s.deps.Session != nil {
		middlewares = append(middlewares, s.deps.Session.Middleware)
	}

	// API security (body size, content-type, GraphQL depth)
	if s.deps.APISec != nil {
		middlewares = append(middlewares, s.deps.APISec.Middleware)
	}

	// Anomaly detection (baseline deviation)
	if s.deps.Anomaly != nil {
		middlewares = append(middlewares, s.deps.Anomaly.Middleware)
	}

	// Custom rule DSL (user-defined rules)
	if s.deps.RuleDSL != nil {
		middlewares = append(middlewares, s.deps.RuleDSL.Middleware)
	}

	// Virtual patching (regex-based emergency patches)
	if s.deps.VPatch != nil {
		middlewares = append(middlewares, s.deps.VPatch.Middleware)
	}

	// URL allowlist — skip WAF for allowlisted paths
	if cfg.URLAllowlist != "" {
		allowPrefixes := splitTrim(cfg.URLAllowlist)
		middlewares = append(middlewares, urlAllowlistMiddleware(allowPrefixes))
	}

	// WAF engine
	wafEngine, err := waf.Build(cfg, s.deps.Logger, s.deps.GeoIP, s.deps.Bot, s.deps.Stats)
	if err != nil {
		return fmt.Errorf("proxy: waf: %w", err)
	}
	if wafEngine != nil {
		middlewares = append(middlewares, wafEngine.Middleware)
	}

	// DLP scanner (response middleware — wraps outgoing responses)
	if s.deps.DLP != nil {
		middlewares = append(middlewares, s.deps.DLP.Middleware)
	}

	// Security response headers
	if s.deps.Headers != nil {
		middlewares = append(middlewares, s.deps.Headers.Middleware)
	}

	// Compose the chain and apply to reverse proxy
	chain := pipeline.Chain(middlewares...)
	s.handler.Store(chain(rp))
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func loggingMiddleware(deps *Deps) pipeline.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rw, r)

			durationMs := time.Since(start).Milliseconds()
			clientIP := axhttp.RealIP(r)
			requestID := uuid.New().String()
			userAgent := r.Header.Get("User-Agent")

			var cc, cn string
			if deps.GeoIP != nil {
				geo := deps.GeoIP.Lookup(clientIP)
				cc = geo.CountryCode
				cn = geo.CountryName
			}

			var botClass string
			if deps.Bot != nil {
				br := deps.Bot.Detect(userAgent)
				botClass = string(br.Classification)
			}

			deps.Logger.LogAccess(r.Method, r.URL.Path, rw.code, durationMs,
				clientIP, r.Host, userAgent, cc, cn, requestID,
				r.ContentLength, int64(rw.written), botClass,
			)

			if deps.Stats != nil {
				deps.Stats.RecordResponseTime(float64(durationMs))
				deps.Stats.RecordRequestLatency(r.Host, float64(durationMs))

				isBot := botClass != "" && botClass != "human"
				deps.Stats.RecordAccessLog(stats.AccessLogEntry{
					IP:          clientIP,
					Country:     cn,
					CountryCode: cc,
					Method:      r.Method,
					Host:        r.Host,
					Path:        r.URL.Path,
					StatusCode:  rw.code,
					LatencyMs:   float64(durationMs),
					BytesIn:     r.ContentLength,
					BytesOut:    int64(rw.written),
					UserAgent:   userAgent,
					IsBot:       isBot,
				})
			}
		})
	}
}

func urlAllowlistMiddleware(prefixes []string) pipeline.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range prefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					// Mark as allowlisted so WAF middleware can skip
					r.Header.Set("X-AXCerberus-Allowlisted", "true")
					break
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hostAllowed(host, domains string) bool {
	if domains == "" {
		return true
	}
	host = stripPort(host)
	for _, d := range splitTrim(domains) {
		if d == host {
			return true
		}
		if strings.HasPrefix(d, "*.") && strings.HasSuffix(host, d[1:]) {
			return true
		}
	}
	return false
}

func isURLBlocked(path, blocklist string) bool {
	if blocklist == "" {
		return false
	}
	for _, p := range splitTrim(blocklist) {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func stripPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

type statusWriter struct {
	http.ResponseWriter
	code    int
	written int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.written += n
	return n, err
}
