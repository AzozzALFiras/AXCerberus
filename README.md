<p align="center">
  <img src="axcerberus_icon.png" alt="AXCerberus" width="200">
</p>

<h1 align="center">AXCerberus WAF</h1>

<p align="center">
  <strong>High-performance Layer 7 Web Application Firewall built in Go</strong><br>
  A standalone reverse-proxy WAF with Coraza engine, DDoS shield, honeypot traps, credential stuffing detection, data leak prevention, and SSRF protection.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go_1.25-00ADD8?logo=go" alt="Go">
  <img src="https://img.shields.io/badge/Engine-Coraza_v3-blue" alt="Coraza">
  <img src="https://img.shields.io/badge/Platform-Linux_amd64_%7C_arm64-333" alt="Platform">
  <img src="https://img.shields.io/badge/CGO-disabled-green" alt="CGO">
  <img src="https://img.shields.io/badge/Version-1.0.0-orange" alt="Version">
  <img src="https://img.shields.io/badge/Tests-14_suites-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/LOC-6810-blue" alt="LOC">
</p>

---

## Overview

AXCerberus is an enterprise-grade Web Application Firewall that operates as a reverse proxy between the internet and your web server. Every HTTP/HTTPS request passes through AXCerberus, gets inspected by 12 independent security modules, and is either forwarded to the upstream server or blocked.

```
Internet → [:80/:443] AXCerberus WAF → [:8181] Nginx/Apache/LiteSpeed → Application
```

It is designed as a plugin for the [AevonX](https://aevonx.app) server management platform, but runs as a standalone Linux binary with zero external dependencies (single static binary, no CGO).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HTTP Request                         │
└───────────────────────┬─────────────────────────────────┘
                        ▼
              ┌─────────────────┐
              │   IP Guard      │  Allow/Blocklist, CIDR, Auto-Escalation
              ├─────────────────┤
              │   GeoIP         │  Country Blocklist/Allowlist (MaxMind)
              ├─────────────────┤
              │   Rate Limiter  │  Sliding Window, Per-IP Per-Endpoint
              ├─────────────────┤
              │   DDoS Shield   │  EWMA Baseline, Spike Detection, 3 Levels
              ├─────────────────┤
              │   Bot Detector  │  52 UA Patterns (18 good, 34 malicious)
              ├─────────────────┤
              │   Honeypot      │  Trap Paths, Fake Pages, Auto-Block
              ├─────────────────┤
              │   SSRF Guard    │  Internal IP, Metadata, Dangerous Schemes
              ├─────────────────┤
              │   Credential    │  Login Velocity, Brute Force Detection
              ├─────────────────┤
              │   Coraza WAF    │  4-Phase Inspection (ModSecurity Rules)
              ├─────────────────┤
              │   DLP Scanner   │  Response Body: CC, API Keys, Stack Traces
              └────────┬────────┘
                       ▼
              ┌─────────────────┐
              │  Upstream Server │  Nginx / Apache / LiteSpeed
              └─────────────────┘
```

All modules implement the `Middleware` interface (`func(http.Handler) http.Handler`) and are composed via `pipeline.Chain()`. Each module can be independently enabled/disabled via `config.avx`.

---

## Security Modules

### 1. Coraza WAF Engine
ModSecurity-compatible rule engine with 4-phase request/response inspection. Ships with 5 rule files covering SQL injection, XSS, path traversal, command injection, Log4Shell, RFI, HTTP smuggling, and sensitive file access.

### 2. IP Guard
Per-IP concurrency limiting with CIDR support. Auto-block escalation: **5 min → 1 hour → 24 hours → permanent**. File-based allow/blocklists.

### 3. GeoIP Blocking
Country-level blocking using MaxMind GeoLite2 database. Two modes: `blocklist` (block listed countries) and `allowlist` (only allow listed countries).

### 4. Adaptive Rate Limiter
Sliding window algorithm (not fixed window) with per-IP per-endpoint tracking. Configurable limits for global (300/min), login (10/min), and API (120/min) endpoints. Optional throttle mode adds progressive delay instead of hard blocking.

### 5. DDoS L7 Shield
EWMA (Exponentially Weighted Moving Average) baseline learning with spike detection. Three auto-mitigation levels. Per-IP connection tracking with configurable limits.

### 6. Bot Detector
User-Agent classification with 52 patterns: 18 verified bots (Googlebot, Bingbot, etc.) and 34 malicious scanners (sqlmap, Nikto, Nuclei, etc.). Scoring: Human, Verified Bot, Likely Bot, Suspicious, Malicious.

### 7. Honeypot Traps
Configurable trap paths (`/wp-admin`, `/phpmyadmin`, `/.env`, `/.git/config`, etc.) that return realistic fake pages. Any IP hitting a trap is auto-blocked. Fake pages: WordPress login, phpMyAdmin, `.env` file, `.git/config`.

### 8. Credential Stuffing Detection
Monitors configurable login paths (POST to `/login`, `/signin`, `/api/auth`, `/wp-login.php`). Tracks per-IP login velocity with sliding window. Auto-blocks on threshold breach.

### 9. Data Leak Prevention (DLP)
Scans response bodies for sensitive data leaks:
- **Credit cards**: Visa, Mastercard, Amex with Luhn validation
- **API keys**: AWS (`AKIA...`), GitHub (`ghp_...`), Stripe (`sk_live_...`)
- **Stack traces**: PHP, Python, Java, Node.js, Go, .NET
- **Database errors**: MySQL, PostgreSQL syntax errors
- **Internal IPs**: 10.x, 172.16-31.x, 192.168.x in responses

Three modes: `block` (return 500), `mask` (replace with `[REDACTED]`), `log` (log only).

### 10. SSRF Prevention
Blocks Server-Side Request Forgery by detecting internal IPs, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), and dangerous URL schemes (`file://`, `gopher://`, `dict://`) in request parameters.

### 11. Alert System
Central dispatcher with webhook delivery. Per-event-type throttling (max N alerts/hour). Severity levels: low, medium, high, critical. Configurable minimum severity threshold.

### 12. Stats API
Local REST API on `127.0.0.1:9443` (accessed via SSH tunnel from AevonX app). Endpoints for real-time metrics, attack timelines, top attackers, DDoS status, honeypot hits, and more.

---

## Project Structure

```
AXCerberus/
├── cmd/axcerberus/
│   └── main.go                     Entry point, signal handling, SIGHUP reload
├── internal/
│   ├── config/config.go            Config loader (config.avx JSON schema)
│   ├── logger/logger.go            4-channel slog (access, error, warning, security)
│   ├── pipeline/pipeline.go        Middleware chain: Chain(m1, m2, ...) → handler
│   ├── proxy/
│   │   ├── server.go               Reverse proxy with middleware composition
│   │   ├── deps.go                 Dependency injection struct
│   │   └── ipguard.go              IP guard with escalated blocking
│   ├── waf/
│   │   ├── engine.go               Coraza WAF builder + attack type mapping
│   │   └── handler.go              4-phase inspection middleware
│   ├── geoip/
│   │   ├── geoip.go                MaxMind DB lookup
│   │   └── blocker.go              Country blocking middleware
│   ├── ratelimit/limiter.go        Sliding window rate limiter
│   ├── bot/detector.go             UA-based bot classification
│   ├── honeypot/
│   │   ├── engine.go               Trap path management + auto-block
│   │   └── pages.go                Fake response pages
│   ├── ddos/shield.go              EWMA baseline + spike detection
│   ├── credential/detector.go      Login velocity tracking
│   ├── dlp/
│   │   ├── scanner.go              Response body scanning middleware
│   │   └── patterns.go             Regex patterns + Luhn validation
│   ├── ssrf/detector.go            Internal IP + metadata detection
│   ├── alert/
│   │   ├── dispatcher.go           Event routing + throttling
│   │   └── webhook.go              HTTP POST JSON sender
│   ├── stats/
│   │   ├── stats.go                In-memory counters (atomic)
│   │   └── api.go                  REST API endpoints
│   └── cli/exec.go                 23 CLI actions for AevonX plugin system
├── tests/                          14 test suites
├── dist/
│   ├── setup.sh                    WAF-specific server setup (158 lines)
│   ├── uninstall.sh                WAF-specific teardown (121 lines)
│   ├── config.avx                  Plugin configuration schema (17 sections)
│   ├── hooks/_manifest.json        Plugin manifest with lifecycle
│   └── rules/*.conf                5 OWASP CRS rule files
├── Makefile
├── go.mod
└── go.sum
```

**Source**: 24 Go files, 14 test files — **6,810 lines of code total**.

---

## Dependencies

| Dependency | Purpose |
|---|---|
| [coraza/v3](https://github.com/corazawaf/coraza) v3.3.3 | ModSecurity-compatible WAF engine |
| [google/uuid](https://github.com/google/uuid) v1.6.0 | Unique request/alert IDs |
| [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang) v1.13.1 | GeoLite2 MaxMind DB reader |

Zero CGO. Single static binary. No runtime dependencies.

---

## Build

```bash
# Prerequisites: Go 1.25+

# Build for Linux x86_64 (most cloud servers)
make build

# Build for Linux ARM64 (AWS Graviton, Oracle Ampere, Raspberry Pi)
make build-arm64

# Build both architectures
make build-all

# Build + package ZIP for deployment
make zip

# Build with specific version
make zip VERSION=1.0.0

# Run tests
make test
```

Output goes to `build/` (excluded from git via `.gitignore`):

```
build/
├── axcerberus-linux-amd64      11 MB static binary
├── axcerberus-linux-arm64      10 MB static binary
└── axcerberus-v1.0.0.zip       8.1 MB deployment package
```

---

## Deployment

AXCerberus is deployed as an AevonX plugin. The ZIP is uploaded to the server via the AevonX app, and the PluginManager handles the full lifecycle automatically.

### What PluginManager handles (from `_manifest.json` lifecycle):
- Directory creation (`/etc/aevonx/plugins/axcerberus/`, `/var/log/aevonx/plugins/axcerberus/`)
- Binary installation with architecture detection (`uname -m`)
- Systemd service generation, enable, and start
- Hook registration and config.avx preservation on upgrades

### What `setup.sh` handles (WAF-specific):
1. Create `aevonx-waf` service user
2. Download GeoLite2 country database
3. Detect web server (Nginx, Apache2, httpd, OpenLiteSpeed, LiteSpeed Enterprise)
4. Shift web server from port 80 to a free port (8181+)
5. Update `config.avx` upstream to point to the shifted web server
6. Create IP allowlist/blocklist files

### What `uninstall.sh` handles (WAF-specific):
1. Read upstream port from config
2. Restore web server back to port 80
3. Restore original Nginx configs (certbot redirects)

### Supported Web Servers
| Server | Service | Config Format |
|--------|---------|---------------|
| Nginx | `nginx` | `listen 80;` directives |
| Apache (Debian/Ubuntu) | `apache2` | `/etc/apache2/ports.conf` |
| Apache (RHEL/CentOS) | `httpd` | `/etc/httpd/conf/httpd.conf` |
| OpenLiteSpeed | `lshttpd` | XML `<address>*:80</address>` |
| LiteSpeed Enterprise | `lsws` | Conf `address *:80` |

### Supported Linux Distributions
Ubuntu 18+, Debian 10+, CentOS 7+, RHEL 8+, AlmaLinux 8+, Rocky Linux 8+, Amazon Linux 2+

---

## Configuration

All settings are managed via `config.avx` (JSON schema format), editable through the AevonX app UI or directly on the server.

**17 configuration sections:**

| Section | Key Settings |
|---------|-------------|
| Network | Listen address, upstream server, TLS cert/key, proxy headers |
| Routing | Allowed domains (wildcard support), path prefixes |
| WAF Protection | Enable/disable, rule files glob, anomaly score threshold |
| IP Guard | Max concurrent per IP, block duration, auto-escalation |
| URL Lists | URL allowlist/blocklist |
| GeoIP Blocking | Database path, blocklist/allowlist mode, country codes |
| Rate Limiting | Global (300/min), login (10/min), API (120/min), throttle mode |
| Bot Detection | Enable/disable UA-based classification |
| Honeypot Traps | Enable, trap paths, auto-block on hit |
| DDoS Shield | Enable, auto-mitigate, spike multiplier, max connections |
| Credential Protection | Enable, login paths, max attempts per IP/username |
| Data Leak Prevention | Enable, mode (block/mask/log), credit cards, API keys, stack traces |
| SSRF Prevention | Enable internal IP + metadata + scheme blocking |
| Alerts | Enable, webhook URL, max per hour, severity threshold |
| Stats API | Enable, listen address (localhost:9443) |
| Timeouts | Read/write timeout seconds |
| Logging | Access, error, warning, security log file paths |

---

## Testing

```bash
make test
```

14 test suites covering all security modules:

| Test Suite | What It Tests |
|---|---|
| `pipeline_test.go` | Middleware chain composition, ordering, blocking |
| `config_test.go` | Config loading, validation, defaults, split helpers |
| `ipguard_test.go` | Allow/block, CIDR, escalation (5min→1hr→24hr→perm) |
| `ratelimit_test.go` | Sliding window, per-endpoint limits, throttle mode |
| `honeypot_test.go` | Trap detection, auto-block callback, fake pages |
| `ddos_test.go` | Baseline learning, connection limits, mitigation levels |
| `credential_test.go` | Brute force detection, callback, multi-path |
| `dlp_test.go` | Luhn validation, CC/API key/stack trace detection, block/mask/log modes |
| `ssrf_test.go` | Internal IP, metadata endpoints, dangerous schemes |
| `alert_test.go` | Dispatch, severity filter, per-type throttling, ring buffer |
| `bot_test.go` | Human, verified bots (5), malicious scanners (7), scoring |
| `stats_test.go` | Counters, protection rate, timelines, top attackers |
| `waf_test.go` | Attack type extraction (12 categories) |
| `geoip_test.go` | Nil safety, country sets, uppercase normalization |

---

## WAF Rules

Ships with 5 Coraza (ModSecurity-compatible) rule files:

| File | Coverage |
|------|----------|
| `default-rules.conf` | SQL injection, XSS, path traversal, LFI, RFI, command injection, Log4Shell, HTTP smuggling, scanner detection, sensitive file access |
| `api-protection.conf` | API endpoint abuse, JSON injection |
| `bot-detection.conf` | Malicious bot User-Agent patterns |
| `php-protection.conf` | PHP eval injection, file upload abuse |
| `wordpress-protection.conf` | WordPress xmlrpc, wp-admin brute force |

Rules use Coraza's `SecRule` syntax with 4-phase inspection:
1. **Phase 1** — Request headers (URI, method, Host)
2. **Phase 2** — Request body (POST parameters, JSON payload)
3. **Phase 3** — Response headers
4. **Phase 4** — Response body (DLP scanning)

---

## Stats API Endpoints

Local REST API on `127.0.0.1:9443` (accessed via SSH tunnel):

```
GET  /api/v1/stats/overview          Full dashboard metrics
GET  /api/v1/stats/timeline          Attack timeline (24h buckets)
GET  /api/v1/stats/attack-types      Attack type distribution
GET  /api/v1/stats/top-attackers     Top blocked IPs
GET  /api/v1/stats/top-uris          Most targeted URIs
GET  /api/v1/stats/countries         Requests by country
GET  /api/v1/stats/domains           Per-domain statistics
GET  /api/v1/ddos/status             DDoS shield status + mitigation level
GET  /api/v1/honeypot/hits           Recent honeypot interactions
GET  /api/v1/credential/status       Credential protection stats
GET  /api/v1/blocklist               Current IP blocklist
GET  /api/v1/allowlist               Current IP allowlist
POST /api/v1/blocklist/add           Add IP to blocklist
POST /api/v1/blocklist/remove        Remove IP from blocklist
POST /api/v1/allowlist/add           Add IP to allowlist
POST /api/v1/allowlist/remove        Remove IP from allowlist
GET  /healthz                        Health check (200 OK)
```

---

## CLI Actions

The binary supports 23 CLI exec actions for integration with the AevonX plugin system:

```bash
axcerberus exec waf.stats.overview
axcerberus exec waf.blocklist.add '{"ip":"1.2.3.4"}'
axcerberus exec waf.service.status
```

---

## License

Copyright (c) 2026 AevonX. All rights reserved.

This software is proprietary and confidential. Unauthorized copying, distribution,
modification, or use of this software, in whole or in part, is strictly prohibited
without prior written permission from AevonX.

For licensing inquiries, contact: contact@aevonx.app
