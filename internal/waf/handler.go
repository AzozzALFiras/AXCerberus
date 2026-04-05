package waf

import (
	"bytes"
	"io"
	"net/http"

	"axcerberus/internal/bot"
	"axcerberus/internal/geoip"
	axhttp "axcerberus/internal/httputil"
	"axcerberus/internal/logger"
	"axcerberus/internal/stats"

	"github.com/corazawaf/coraza/v3"
	"github.com/google/uuid"
)

type handler struct {
	waf      coraza.WAF
	next     http.Handler
	logs     *logger.Logs
	geoDB    *geoip.DB
	botDet   *bot.Detector
	statsEng *stats.Engine
}

func newHandler(wafInstance coraza.WAF, next http.Handler, logs *logger.Logs,
	geoDB *geoip.DB, botDet *bot.Detector, statsEng *stats.Engine,
) http.Handler {
	return &handler{waf: wafInstance, next: next, logs: logs, geoDB: geoDB, botDet: botDet, statsEng: statsEng}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Skip WAF for URL-allowlisted paths
	if r.Header.Get("X-AXCerberus-Allowlisted") == "true" {
		r.Header.Del("X-AXCerberus-Allowlisted")
		h.next.ServeHTTP(w, r)
		return
	}

	requestID := uuid.New().String()
	clientIP := axhttp.RealIP(r)
	host := r.Host
	userAgent := r.Header.Get("User-Agent")

	var countryCode, countryName string
	if h.geoDB != nil {
		geo := h.geoDB.Lookup(clientIP)
		countryCode = geo.CountryCode
		countryName = geo.CountryName
	}

	if h.botDet != nil {
		botResult := h.botDet.Detect(userAgent)
		if h.statsEng != nil {
			h.statsEng.RecordBot(botResult.IsBot)
		}
	}

	var bytesIn int64
	if r.ContentLength > 0 {
		bytesIn = r.ContentLength
	}

	tx := h.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			h.logs.Error.Error("waf_tx_close", "error", err)
		}
	}()

	// Phase 1: Connection + URI + Headers
	tx.ProcessConnection(clientIP, 0, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vals := range r.Header {
		for _, v := range vals {
			tx.AddRequestHeader(k, v)
		}
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		attackType := ExtractAttackType(it.RuleID)
		h.logBlock(requestID, it.RuleID, "request headers", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
		if h.statsEng != nil {
			h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
			h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
		}
		h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "request headers", userAgent)
		http.Error(w, http.StatusText(it.Status), it.Status)
		return
	}

	// Phase 2: Request body
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil && len(body) > 0 {
			bytesIn = int64(len(body))
			if it, _, wErr := tx.WriteRequestBody(body); wErr != nil {
				h.logs.Error.Error("waf_req_body_write", "error", wErr)
			} else if it != nil {
				attackType := ExtractAttackType(it.RuleID)
				h.logBlock(requestID, it.RuleID, "request body write", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
				if h.statsEng != nil {
					h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
					h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
				}
				h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "request body write", userAgent)
				http.Error(w, http.StatusText(it.Status), it.Status)
				return
			}
		}
	}

	if it, err := tx.ProcessRequestBody(); err != nil {
		h.logs.Error.Error("waf_req_body_process", "error", err)
	} else if it != nil {
		attackType := ExtractAttackType(it.RuleID)
		h.logBlock(requestID, it.RuleID, "request body", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
		if h.statsEng != nil {
			h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
			h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
		}
		h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "request body", userAgent)
		http.Error(w, http.StatusText(it.Status), it.Status)
		return
	}

	if bodyReader, err := tx.RequestBodyReader(); err == nil && bodyReader != nil {
		r.Body = io.NopCloser(bodyReader)
	}

	// Phase 3 & 4: Proxy + response inspection
	rec := &responseRecorder{header: make(http.Header), buf: &bytes.Buffer{}, statusCode: http.StatusOK}
	h.next.ServeHTTP(rec, r)

	for k, vals := range rec.header {
		for _, v := range vals {
			tx.AddResponseHeader(k, v)
		}
	}
	if it := tx.ProcessResponseHeaders(rec.statusCode, "HTTP/1.1"); it != nil {
		attackType := ExtractAttackType(it.RuleID)
		h.logBlock(requestID, it.RuleID, "response headers", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
		if h.statsEng != nil {
			h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
			h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
		}
		h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "response headers", userAgent)
		http.Error(w, http.StatusText(it.Status), it.Status)
		return
	}

	if rec.buf.Len() > 0 {
		if it, _, err := tx.WriteResponseBody(rec.buf.Bytes()); err != nil {
			h.logs.Error.Error("waf_resp_body_write", "error", err)
		} else if it != nil {
			attackType := ExtractAttackType(it.RuleID)
			h.logBlock(requestID, it.RuleID, "response body", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
			if h.statsEng != nil {
				h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
				h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
			}
			h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "response body", userAgent)
			http.Error(w, http.StatusText(it.Status), it.Status)
			return
		}
	}

	if it, err := tx.ProcessResponseBody(); err != nil {
		h.logs.Error.Error("waf_resp_body_process", "error", err)
	} else if it != nil {
		attackType := ExtractAttackType(it.RuleID)
		h.logBlock(requestID, it.RuleID, "response body process", clientIP, r.URL.Path, attackType, countryCode, countryName, userAgent)
		if h.statsEng != nil {
			h.statsEng.RecordRequest(host, true, it.Status, bytesIn, 0)
			h.statsEng.RecordAttack(clientIP, countryName, countryCode, attackType, r.URL.Path)
		}
		h.recordBlock(r.Method, host, r.URL.Path, clientIP, countryName, countryCode, attackType, "response body process", userAgent)
		http.Error(w, http.StatusText(it.Status), it.Status)
		return
	}

	// Forward clean response
	bytesOut := int64(rec.buf.Len())
	for k, vals := range rec.header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(rec.statusCode)
	io.Copy(w, rec.buf)

	if h.statsEng != nil {
		h.statsEng.RecordRequest(host, false, rec.statusCode, bytesIn, bytesOut)
	}
}

func (h *handler) logBlock(requestID string, ruleID int, phase, clientIP, path, attackType, cc, cn, ua string) {
	h.logs.LogSecurity("warn", "waf_blocked",
		ruleID, "critical", "Blocked at "+phase+" phase",
		clientIP, path, attackType, cc, cn, ua, requestID, 0, true,
	)
}

func (h *handler) recordBlock(method, host, path, clientIP, countryName, countryCode, attackType, phase, userAgent string) {
	if h.statsEng == nil {
		return
	}
	h.statsEng.RecordBlockLog(stats.BlockLogEntry{
		IP:          clientIP,
		Country:     countryName,
		CountryCode: countryCode,
		Method:      method,
		Host:        host,
		Path:        path,
		Rule:        attackType,
		Reason:      "Blocked at " + phase + " phase",
		Severity:    "critical",
		UserAgent:   userAgent,
	})
}

type responseRecorder struct {
	header     http.Header
	buf        *bytes.Buffer
	statusCode int
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) WriteHeader(code int)        { r.statusCode = code }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.buf.Write(b) }
