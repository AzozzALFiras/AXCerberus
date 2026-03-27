// Package stats provides an in-memory real-time statistics engine.
package stats

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Engine is the central statistics collector. All methods are goroutine-safe.
type Engine struct {
	mu sync.RWMutex

	totalRequests   atomic.Int64
	blockedRequests atomic.Int64
	bytesIn         atomic.Int64
	bytesOut        atomic.Int64

	attackTypes    map[string]int64
	countries      map[string]int64
	statusCodes    map[int]int64
	domains        map[string]*DomainStats
	attackerCounts map[string]*AttackerInfo
	uriCounts      map[string]int64
	timeline       [24]HourBucket
	qps            *qpsTracker
	responseTimes  []float64

	botRequests   atomic.Int64
	humanRequests atomic.Int64

	// New module counters
	honeypotHits       atomic.Int64
	credentialAttacks  atomic.Int64
	dlpEvents          atomic.Int64
	ddosLevel          atomic.Int32

	startTime time.Time
	Events    *EventBus

	// Ring buffers for logs
	accessLog    [500]AccessLogEntry
	accessLogIdx int
	accessLogLen int
	blockLog     [500]BlockLogEntry
	blockLogIdx  int
	blockLogLen  int
}

type DomainStats struct {
	TotalRequests   int64 `json:"total_requests"`
	BlockedRequests int64 `json:"blocked_requests"`
	BytesIn         int64 `json:"bytes_in"`
	BytesOut        int64 `json:"bytes_out"`
}

type AttackerInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Attacks     int64  `json:"attacks"`
	LastSeen    string `json:"last_seen"`
}

type HourBucket struct {
	Hour    int   `json:"hour"`
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
	Allowed int64 `json:"allowed"`
}

type URICount struct {
	URI   string `json:"uri"`
	Count int64  `json:"count"`
}

type CountryCount struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Count       int64  `json:"count"`
}

type AttackTypeCount struct {
	Type  string `json:"type"`
	Count int64  `json:"count"`
}

type ResponseTimeStats struct {
	P50     float64 `json:"p50"`
	P95     float64 `json:"p95"`
	P99     float64 `json:"p99"`
	Avg     float64 `json:"avg"`
	Max     float64 `json:"max"`
	Samples int     `json:"samples"`
}

type StatusCodeCount struct {
	Code  int   `json:"code"`
	Count int64 `json:"count"`
}

type BotDetails struct {
	TotalBot   int64   `json:"total_bot"`
	TotalHuman int64   `json:"total_human"`
	BotRate    float64 `json:"bot_rate"`
}

// AccessLogEntry records a single proxied request.
type AccessLogEntry struct {
	Timestamp   string `json:"timestamp"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	LatencyMs   float64 `json:"latency_ms"`
	BytesIn     int64  `json:"bytes_in"`
	BytesOut    int64  `json:"bytes_out"`
	UserAgent   string `json:"user_agent"`
	IsBot       bool   `json:"is_bot"`
}

// BlockLogEntry records a single blocked request with the reason.
type BlockLogEntry struct {
	Timestamp   string `json:"timestamp"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Rule        string `json:"rule"`
	Reason      string `json:"reason"`
	Severity    string `json:"severity"`
	UserAgent   string `json:"user_agent"`
}

type Overview struct {
	TotalRequests       int64   `json:"total_requests"`
	BlockedRequests     int64   `json:"blocked_requests"`
	AllowedRequests     int64   `json:"allowed_requests"`
	ProtectionRate      float64 `json:"protection_rate"`
	QPS                 float64 `json:"qps"`
	BytesIn             int64   `json:"bytes_in"`
	BytesOut            int64   `json:"bytes_out"`
	BotRequests         int64   `json:"bot_requests"`
	HumanRequests       int64   `json:"human_requests"`
	UptimeSeconds       int64   `json:"uptime_seconds"`
	HoneypotHitsToday   int64   `json:"honeypot_hits_today"`
	CredentialAttacks   int64   `json:"credential_attacks_today"`
	DLPEventsToday      int64   `json:"dlp_events_today"`
	DDoSLevel           int32   `json:"ddos_level"`
}

func New() *Engine {
	return &Engine{
		attackTypes:    make(map[string]int64),
		countries:      make(map[string]int64),
		statusCodes:    make(map[int]int64),
		domains:        make(map[string]*DomainStats),
		attackerCounts: make(map[string]*AttackerInfo),
		uriCounts:      make(map[string]int64),
		responseTimes:  make([]float64, 0, 10000),
		qps:            newQPSTracker(),
		startTime:      time.Now(),
		Events:         NewEventBus(),
	}
}

func (e *Engine) RecordRequest(host string, blocked bool, statusCode int, bytesIn, bytesOut int64) {
	e.totalRequests.Add(1)
	e.bytesIn.Add(bytesIn)
	e.bytesOut.Add(bytesOut)
	e.qps.tick()

	if blocked {
		e.blockedRequests.Add(1)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.statusCodes[statusCode]++
	hour := time.Now().Hour()
	e.timeline[hour].Hour = hour
	e.timeline[hour].Total++
	if blocked {
		e.timeline[hour].Blocked++
	} else {
		e.timeline[hour].Allowed++
	}

	if host != "" {
		ds, ok := e.domains[host]
		if !ok {
			ds = &DomainStats{}
			e.domains[host] = ds
		}
		ds.TotalRequests++
		ds.BytesIn += bytesIn
		ds.BytesOut += bytesOut
		if blocked {
			ds.BlockedRequests++
		}
	}
}

func (e *Engine) RecordAttack(ip, country, countryCode, attackType, uri string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if attackType != "" {
		e.attackTypes[attackType]++
	}
	if countryCode != "" {
		e.countries[countryCode+"|"+country]++
	}

	info, ok := e.attackerCounts[ip]
	if !ok {
		info = &AttackerInfo{IP: ip, Country: country, CountryCode: countryCode}
		e.attackerCounts[ip] = info
	}
	info.Attacks++
	info.LastSeen = time.Now().UTC().Format(time.RFC3339)

	if uri != "" {
		e.uriCounts[uri]++
	}
}

func (e *Engine) RecordResponseTime(ms float64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.responseTimes) < 100000 {
		e.responseTimes = append(e.responseTimes, ms)
	}
}

func (e *Engine) RecordBot(isBot bool) {
	if isBot {
		e.botRequests.Add(1)
	} else {
		e.humanRequests.Add(1)
	}
}

func (e *Engine) RecordHoneypotHit()       { e.honeypotHits.Add(1) }
func (e *Engine) RecordCredentialAttack()   { e.credentialAttacks.Add(1) }
func (e *Engine) RecordDLPEvent()           { e.dlpEvents.Add(1) }
func (e *Engine) SetDDoSLevel(level int32)  { e.ddosLevel.Store(level) }

func (e *Engine) GetOverview() Overview {
	total := e.totalRequests.Load()
	blocked := e.blockedRequests.Load()
	allowed := total - blocked
	var rate float64
	if total > 0 {
		rate = float64(blocked) / float64(total) * 100
	}
	return Overview{
		TotalRequests:     total,
		BlockedRequests:   blocked,
		AllowedRequests:   allowed,
		ProtectionRate:    rate,
		QPS:               e.qps.rate(),
		BytesIn:           e.bytesIn.Load(),
		BytesOut:          e.bytesOut.Load(),
		BotRequests:       e.botRequests.Load(),
		HumanRequests:     e.humanRequests.Load(),
		UptimeSeconds:     int64(time.Since(e.startTime).Seconds()),
		HoneypotHitsToday: e.honeypotHits.Load(),
		CredentialAttacks: e.credentialAttacks.Load(),
		DLPEventsToday:    e.dlpEvents.Load(),
		DDoSLevel:         e.ddosLevel.Load(),
	}
}

func (e *Engine) GetTimeline() []HourBucket {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]HourBucket, 24)
	now := time.Now().Hour()
	for i := 0; i < 24; i++ {
		idx := (now - 23 + i + 24) % 24
		result[i] = e.timeline[idx]
	}
	return result
}

func (e *Engine) GetAttackTypes() []AttackTypeCount {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]AttackTypeCount, 0, len(e.attackTypes))
	for t, c := range e.attackTypes {
		result = append(result, AttackTypeCount{Type: t, Count: c})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result
}

func (e *Engine) GetCountries() []CountryCount {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]CountryCount, 0, len(e.countries))
	for key, c := range e.countries {
		code, name := splitCountryKey(key)
		result = append(result, CountryCount{CountryCode: code, CountryName: name, Count: c})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result
}

func (e *Engine) GetTopAttackers(limit int) []AttackerInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]AttackerInfo, 0, len(e.attackerCounts))
	for _, info := range e.attackerCounts {
		result = append(result, *info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Attacks > result[j].Attacks })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (e *Engine) GetTopURIs(limit int) []URICount {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]URICount, 0, len(e.uriCounts))
	for uri, c := range e.uriCounts {
		result = append(result, URICount{URI: uri, Count: c})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result
}

func (e *Engine) GetDomains() map[string]*DomainStats {
	e.mu.RLock()
	defer e.mu.RUnlock()
	cp := make(map[string]*DomainStats, len(e.domains))
	for k, v := range e.domains {
		clone := *v
		cp[k] = &clone
	}
	return cp
}

func (e *Engine) GetQPS() float64 { return e.qps.rate() }

// GetResponseTimePercentiles returns latency p50, p95, p99, avg, max.
func (e *Engine) GetResponseTimePercentiles() ResponseTimeStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	n := len(e.responseTimes)
	if n == 0 {
		return ResponseTimeStats{}
	}

	sorted := make([]float64, n)
	copy(sorted, e.responseTimes)
	sort.Float64s(sorted)

	var sum float64
	for _, v := range sorted {
		sum += v
	}

	return ResponseTimeStats{
		P50:     sorted[n*50/100],
		P95:     sorted[n*95/100],
		P99:     sorted[min(n*99/100, n-1)],
		Avg:     sum / float64(n),
		Max:     sorted[n-1],
		Samples: n,
	}
}

// GetStatusCodes returns the HTTP status code distribution.
func (e *Engine) GetStatusCodes() []StatusCodeCount {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]StatusCodeCount, 0, len(e.statusCodes))
	for code, count := range e.statusCodes {
		result = append(result, StatusCodeCount{Code: code, Count: count})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Count > result[j].Count })
	return result
}

// GetBotDetails returns bot vs human traffic breakdown.
func (e *Engine) GetBotDetails() BotDetails {
	bot := e.botRequests.Load()
	human := e.humanRequests.Load()
	total := bot + human
	var botRate float64
	if total > 0 {
		botRate = float64(bot) / float64(total) * 100
	}
	return BotDetails{
		TotalBot:   bot,
		TotalHuman: human,
		BotRate:    botRate,
	}
}

// RecordAccessLog adds an entry to the access log ring buffer.
func (e *Engine) RecordAccessLog(entry AccessLogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.accessLog[e.accessLogIdx] = entry
	e.accessLogIdx = (e.accessLogIdx + 1) % len(e.accessLog)
	if e.accessLogLen < len(e.accessLog) {
		e.accessLogLen++
	}
}

// RecordBlockLog adds an entry to the block log ring buffer.
func (e *Engine) RecordBlockLog(entry BlockLogEntry) {
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.blockLog[e.blockLogIdx] = entry
	e.blockLogIdx = (e.blockLogIdx + 1) % len(e.blockLog)
	if e.blockLogLen < len(e.blockLog) {
		e.blockLogLen++
	}
}

// GetAccessLog returns recent access log entries, newest first.
func (e *Engine) GetAccessLog(limit int) []AccessLogEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > e.accessLogLen {
		limit = e.accessLogLen
	}
	result := make([]AccessLogEntry, limit)
	for i := 0; i < limit; i++ {
		idx := (e.accessLogIdx - 1 - i + len(e.accessLog)) % len(e.accessLog)
		result[i] = e.accessLog[idx]
	}
	return result
}

// GetBlockLog returns recent block log entries, newest first.
func (e *Engine) GetBlockLog(limit int) []BlockLogEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 || limit > e.blockLogLen {
		limit = e.blockLogLen
	}
	result := make([]BlockLogEntry, limit)
	for i := 0; i < limit; i++ {
		idx := (e.blockLogIdx - 1 - i + len(e.blockLog)) % len(e.blockLog)
		result[i] = e.blockLog[idx]
	}
	return result
}

func splitCountryKey(key string) (code, name string) {
	for i, c := range key {
		if c == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, key
}

// ---------------------------------------------------------------------------
// QPS tracker — sliding window
// ---------------------------------------------------------------------------

type qpsTracker struct {
	mu       sync.Mutex
	counts   [60]int64
	current  int
	lastTick time.Time
}

func newQPSTracker() *qpsTracker {
	return &qpsTracker{lastTick: time.Now()}
}

func (q *qpsTracker) tick() {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	sec := now.Second()
	if sec != q.current {
		q.counts[sec] = 0
		q.current = sec
	}
	q.counts[sec]++
	q.lastTick = now
}

func (q *qpsTracker) rate() float64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := time.Now()
	if now.Sub(q.lastTick) > 5*time.Second {
		return 0
	}
	sec := now.Second()
	var total int64
	for i := 0; i < 5; i++ {
		idx := (sec - i + 60) % 60
		total += q.counts[idx]
	}
	return float64(total) / 5.0
}
