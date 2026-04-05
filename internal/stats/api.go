// Package stats — HTTP API server for real-time WAF statistics.
// Listens on 127.0.0.1 only. No external network exposure.
package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"axcerberus/internal/alert"
	"axcerberus/internal/anomaly"
	"axcerberus/internal/compliance"
	"axcerberus/internal/credential"
	"axcerberus/internal/ddos"
	"axcerberus/internal/honeypot"
	"axcerberus/internal/ruledsl"
	"axcerberus/internal/session"
	"axcerberus/internal/threatfeed"
)

// APIServer serves the stats API on localhost.
type APIServer struct {
	engine   *Engine
	addr     string
	srv      *http.Server

	// Module references for extended endpoints
	honeypot   *honeypot.Engine
	ddos       *ddos.Shield
	credential *credential.Detector
	alerts     *alert.Dispatcher
	threatFeed *threatfeed.Manager
	anomaly    *anomaly.Detector
	session    *session.Tracker
	ruleDSL    *ruledsl.Engine
	wafState   *compliance.WAFState
}

// NewAPIServer creates a stats API server.
func NewAPIServer(engine *Engine, addr string) *APIServer {
	s := &APIServer{engine: engine, addr: addr}

	mux := http.NewServeMux()

	// Core stats
	mux.HandleFunc("/api/v1/stats/overview", s.handleOverview)
	mux.HandleFunc("/api/v1/stats/timeline", s.handleTimeline)
	mux.HandleFunc("/api/v1/stats/attack-types", s.handleAttackTypes)
	mux.HandleFunc("/api/v1/stats/countries", s.handleCountries)
	mux.HandleFunc("/api/v1/stats/top-attackers", s.handleTopAttackers)
	mux.HandleFunc("/api/v1/stats/top-uris", s.handleTopURIs)
	mux.HandleFunc("/api/v1/stats/domains", s.handleDomains)
	mux.HandleFunc("/api/v1/stats/qps", s.handleQPS)

	// New module endpoints
	mux.HandleFunc("/api/v1/ddos/status", s.handleDDoSStatus)
	mux.HandleFunc("/api/v1/credential/status", s.handleCredentialStatus)
	mux.HandleFunc("/api/v1/honeypot/hits", s.handleHoneypotHits)

	// Extended stats
	mux.HandleFunc("/api/v1/stats/response-times", s.handleResponseTimes)
	mux.HandleFunc("/api/v1/stats/status-codes", s.handleStatusCodes)
	mux.HandleFunc("/api/v1/stats/bot-details", s.handleBotDetails)
	mux.HandleFunc("/api/v1/alerts/recent", s.handleAlertsRecent)

	// Request logs
	mux.HandleFunc("/api/v1/logs/access", s.handleAccessLog)
	mux.HandleFunc("/api/v1/logs/blocks", s.handleBlockLog)

	// Per-domain stats
	mux.HandleFunc("/api/v1/stats/domain-timeline", s.handleDomainTimeline)
	mux.HandleFunc("/api/v1/stats/domain-countries", s.handleDomainCountries)
	mux.HandleFunc("/api/v1/logs/access/domain", s.handleDomainAccessLog)
	mux.HandleFunc("/api/v1/logs/blocks/domain", s.handleDomainBlockLog)

	// Real-time event stream (SSE)
	mux.HandleFunc("/api/v1/stream/events", engine.Events.HandleSSE)

	// Threat feed
	mux.HandleFunc("/api/v1/threatfeed/status", s.handleThreatFeedStatus)
	mux.HandleFunc("/api/v1/threatfeed/update", s.handleThreatFeedUpdate)

	// Anomaly detection
	mux.HandleFunc("/api/v1/anomaly/status", s.handleAnomalyStatus)

	// Session tracking
	mux.HandleFunc("/api/v1/session/status", s.handleSessionStatus)

	// Custom rules
	mux.HandleFunc("/api/v1/rules/list", s.handleRulesList)
	mux.HandleFunc("/api/v1/rules/add", s.handleRulesAdd)
	mux.HandleFunc("/api/v1/rules/remove", s.handleRulesRemove)

	// Compliance
	mux.HandleFunc("/api/v1/compliance/report", s.handleComplianceReport)

	// Health
	mux.HandleFunc("/healthz", s.handleHealth)

	s.srv = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	return s
}

// SetModules sets module references for extended API endpoints.
func (s *APIServer) SetModules(hp *honeypot.Engine, dd *ddos.Shield, cred *credential.Detector) {
	s.honeypot = hp
	s.ddos = dd
	s.credential = cred
}

// SetAlerts sets the alert dispatcher reference.
func (s *APIServer) SetAlerts(a *alert.Dispatcher) {
	s.alerts = a
}

// SetThreatFeed sets the threat feed manager reference.
func (s *APIServer) SetThreatFeed(tf *threatfeed.Manager) {
	s.threatFeed = tf
}

// SetAnomaly sets the anomaly detector reference.
func (s *APIServer) SetAnomaly(a *anomaly.Detector) {
	s.anomaly = a
}

// SetSession sets the session tracker reference.
func (s *APIServer) SetSession(st *session.Tracker) {
	s.session = st
}

// SetRuleDSL sets the custom rule engine reference.
func (s *APIServer) SetRuleDSL(r *ruledsl.Engine) {
	s.ruleDSL = r
}

// SetWAFState sets the WAF state for compliance reporting.
func (s *APIServer) SetWAFState(ws *compliance.WAFState) {
	s.wafState = ws
}

// Serve starts the API server, blocking until ctx is cancelled.
func (s *APIServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.srv.Shutdown(shutCtx)
	}()
	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("stats api: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleOverview(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetOverview())
}

func (s *APIServer) handleTimeline(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"timeline": s.engine.GetTimeline()})
}

func (s *APIServer) handleAttackTypes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"attack_types": s.engine.GetAttackTypes()})
}

func (s *APIServer) handleCountries(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"countries": s.engine.GetCountries()})
}

func (s *APIServer) handleTopAttackers(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"attackers": s.engine.GetTopAttackers(limit)})
}

func (s *APIServer) handleTopURIs(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"uris": s.engine.GetTopURIs(limit)})
}

func (s *APIServer) handleDomains(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"domains": s.engine.GetDomains()})
}

func (s *APIServer) handleQPS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"qps": s.engine.GetQPS()})
}

// ---------------------------------------------------------------------------
// Module handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleDDoSStatus(w http.ResponseWriter, r *http.Request) {
	if s.ddos == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.ddos.GetStatus())
}

func (s *APIServer) handleCredentialStatus(w http.ResponseWriter, r *http.Request) {
	if s.credential == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.credential.GetStats())
}

func (s *APIServer) handleHoneypotHits(w http.ResponseWriter, r *http.Request) {
	if s.honeypot == nil {
		writeJSON(w, map[string]any{"hits": []any{}})
		return
	}
	limit := queryInt(r, "limit", 50)
	writeJSON(w, map[string]any{"hits": s.honeypot.GetHits(limit)})
}

// ---------------------------------------------------------------------------
// Extended stats handlers
// ---------------------------------------------------------------------------

func (s *APIServer) handleResponseTimes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetResponseTimePercentiles())
}

func (s *APIServer) handleStatusCodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status_codes": s.engine.GetStatusCodes()})
}

func (s *APIServer) handleBotDetails(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.engine.GetBotDetails())
}

func (s *APIServer) handleAlertsRecent(w http.ResponseWriter, r *http.Request) {
	if s.alerts == nil {
		writeJSON(w, map[string]any{"alerts": []any{}, "count": 0})
		return
	}
	limit := queryInt(r, "limit", 50)
	alerts := s.alerts.GetRecent(limit)
	writeJSON(w, map[string]any{"alerts": alerts, "count": len(alerts)})
}

func (s *APIServer) handleAccessLog(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	writeJSON(w, map[string]any{"entries": s.engine.GetAccessLog(limit), "total": s.engine.accessLogLen})
}

func (s *APIServer) handleBlockLog(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	writeJSON(w, map[string]any{"entries": s.engine.GetBlockLog(limit), "total": s.engine.blockLogLen})
}

// Per-domain endpoints

func (s *APIServer) handleDomainTimeline(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"domain": domain, "timeline": s.engine.GetDomainTimeline(domain)})
}

func (s *APIServer) handleDomainCountries(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]any{"domain": domain, "countries": s.engine.GetDomainCountries(domain)})
}

func (s *APIServer) handleDomainAccessLog(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}
	limit := queryInt(r, "limit", 100)
	entries := s.engine.GetDomainAccessLog(domain, limit)
	writeJSON(w, map[string]any{"entries": entries, "total": len(entries)})
}

func (s *APIServer) handleDomainBlockLog(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain required"}`, http.StatusBadRequest)
		return
	}
	limit := queryInt(r, "limit", 100)
	entries := s.engine.GetDomainBlockLog(domain, limit)
	writeJSON(w, map[string]any{"entries": entries, "total": len(entries)})
}

func (s *APIServer) handleThreatFeedStatus(w http.ResponseWriter, r *http.Request) {
	if s.threatFeed == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.threatFeed.GetStatus())
}

func (s *APIServer) handleThreatFeedUpdate(w http.ResponseWriter, r *http.Request) {
	if s.threatFeed == nil {
		writeJSON(w, map[string]any{"enabled": false, "error": "threat feed not enabled"})
		return
	}
	s.threatFeed.Update()
	writeJSON(w, s.threatFeed.GetStatus())
}

func (s *APIServer) handleAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	if s.anomaly == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.anomaly.GetStats())
}

func (s *APIServer) handleSessionStatus(w http.ResponseWriter, r *http.Request) {
	if s.session == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, s.session.GetStats())
}

func (s *APIServer) handleRulesList(w http.ResponseWriter, r *http.Request) {
	if s.ruleDSL == nil {
		writeJSON(w, map[string]any{"enabled": false, "rules": []any{}})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "rules": s.ruleDSL.ListRules()})
}

func (s *APIServer) handleRulesAdd(w http.ResponseWriter, r *http.Request) {
	if s.ruleDSL == nil {
		writeJSON(w, map[string]any{"error": "custom rules not enabled"})
		return
	}
	id := r.URL.Query().Get("id")
	raw := r.URL.Query().Get("rule")
	if id == "" || raw == "" {
		writeJSON(w, map[string]any{"error": "id and rule query params required"})
		return
	}
	if err := s.ruleDSL.AddRule(id, raw); err != nil {
		writeJSON(w, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": id})
}

func (s *APIServer) handleRulesRemove(w http.ResponseWriter, r *http.Request) {
	if s.ruleDSL == nil {
		writeJSON(w, map[string]any{"error": "custom rules not enabled"})
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		writeJSON(w, map[string]any{"error": "id query param required"})
		return
	}
	removed := s.ruleDSL.RemoveRule(id)
	writeJSON(w, map[string]any{"ok": removed, "id": id})
}

func (s *APIServer) handleComplianceReport(w http.ResponseWriter, r *http.Request) {
	if s.wafState == nil {
		writeJSON(w, map[string]any{"error": "compliance state not configured"})
		return
	}
	report := compliance.GeneratePCIDSS(*s.wafState)
	writeJSON(w, report)
}

func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache")
	json.NewEncoder(w).Encode(v)
}

func queryInt(r *http.Request, key string, fallback int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
