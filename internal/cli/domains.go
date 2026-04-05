// Package cli — domain management actions for Cerberus WAF.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

func init() {
	actions["waf.domains.list"] = actionDomainsList
	actions["waf.domains.add"] = actionDomainsAdd
	actions["waf.domains.remove"] = actionDomainsRemove
	actions["waf.domains.enable"] = actionDomainsEnable
	actions["waf.domains.disable"] = actionDomainsDisable
	actions["waf.domains.sync"] = actionDomainsSync
	actions["waf.domains.detect_server"] = actionDomainsDetectServer
}

// DomainInfo describes a website domain managed by the WAF.
type DomainInfo struct {
	Domain    string `json:"domain"`
	Enabled   bool   `json:"enabled"`
	WebServer string `json:"web_server"`
}

// ─── Actions ────────────────────────────────────────────────────────

func actionDomainsList(_ []string) (any, error) {
	domains, err := loadDomains()
	if err != nil {
		return nil, err
	}
	return map[string]any{"domains": domains, "count": len(domains)}, nil
}

func actionDomainsAdd(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domains.add <domain>")
	}
	domain := strings.TrimSpace(args[0])
	domains, err := loadDomains()
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		if d.Domain == domain {
			return map[string]any{"added": false, "reason": "already exists"}, nil
		}
	}
	ws := detectActiveWebServer()
	domains = append(domains, DomainInfo{Domain: domain, Enabled: true, WebServer: ws})
	if err := saveDomains(domains); err != nil {
		return nil, err
	}
	updateConfigDomains(domains)
	reloadService()
	return map[string]any{"added": true, "domain": domain}, nil
}

func actionDomainsRemove(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domains.remove <domain>")
	}
	domain := strings.TrimSpace(args[0])
	domains, err := loadDomains()
	if err != nil {
		return nil, err
	}
	var filtered []DomainInfo
	removed := false
	for _, d := range domains {
		if d.Domain == domain {
			removed = true
			continue
		}
		filtered = append(filtered, d)
	}
	if !removed {
		return map[string]any{"removed": false, "reason": "not found"}, nil
	}
	if filtered == nil {
		filtered = make([]DomainInfo, 0)
	}
	if err := saveDomains(filtered); err != nil {
		return nil, err
	}
	updateConfigDomains(filtered)
	reloadService()
	return map[string]any{"removed": true, "domain": domain}, nil
}

func actionDomainsEnable(args []string) (any, error) {
	return setDomainEnabled(args, true)
}

func actionDomainsDisable(args []string) (any, error) {
	return setDomainEnabled(args, false)
}

func actionDomainsSync(_ []string) (any, error) {
	detected := detectServerDomains()
	domains, _ := loadDomains()
	existing := make(map[string]bool)
	for _, d := range domains {
		existing[d.Domain] = true
	}
	added := 0
	for _, d := range detected {
		if !existing[d.Domain] {
			domains = append(domains, d)
			added++
		}
	}
	if added > 0 {
		if err := saveDomains(domains); err != nil {
			return nil, err
		}
		updateConfigDomains(domains)
		reloadService()
	}
	return map[string]any{
		"synced":     added,
		"total":      len(domains),
		"web_server": detectActiveWebServer(),
	}, nil
}

func actionDomainsDetectServer(_ []string) (any, error) {
	ws := detectActiveWebServer()
	port := detectUpstreamPort(ws)
	status := "inactive"
	if ws != "" {
		out, err := exec.Command("systemctl", "is-active", ws).Output()
		if err == nil {
			status = strings.TrimSpace(string(out))
		}
	}
	return map[string]any{
		"type":   ws,
		"port":   port,
		"status": status,
	}, nil
}

// ─── Helpers ────────────────────────────────────────────────────────

func setDomainEnabled(args []string, enabled bool) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domains.enable/disable <domain>")
	}
	domain := strings.TrimSpace(args[0])
	domains, err := loadDomains()
	if err != nil {
		return nil, err
	}
	found := false
	for i := range domains {
		if domains[i].Domain == domain {
			domains[i].Enabled = enabled
			found = true
			break
		}
	}
	if !found {
		return map[string]any{"ok": false, "reason": "not found"}, nil
	}
	if err := saveDomains(domains); err != nil {
		return nil, err
	}
	updateConfigDomains(domains)
	reloadService()

	// Switch nginx config: WAF proxy ↔ direct serving
	if err := switchNginxConfig(domain, enabled); err != nil {
		return map[string]any{"ok": true, "domain": domain, "enabled": enabled, "nginx_warning": err.Error()}, nil
	}

	return map[string]any{"ok": true, "domain": domain, "enabled": enabled}, nil
}

const domainsFile = confDir + "/domains.json"

func loadDomains() ([]DomainInfo, error) {
	data, err := os.ReadFile(domainsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]DomainInfo, 0), nil
		}
		return nil, err
	}
	var domains []DomainInfo
	if err := json.Unmarshal(data, &domains); err != nil {
		return make([]DomainInfo, 0), nil
	}
	if domains == nil {
		return make([]DomainInfo, 0), nil
	}
	return domains, nil
}

func saveDomains(domains []DomainInfo) error {
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(domainsFile, data, 0o644)
}

func updateConfigDomains(domains []DomainInfo) {
	var enabled []string
	for _, d := range domains {
		if d.Enabled {
			enabled = append(enabled, d.Domain)
		}
	}
	value := strings.Join(enabled, ",")
	_ = setConfigKey("domains", value)
}

// switchNginxConfig toggles a site between WAF proxy mode and direct serving.
// enabled=true  → WAF proxy config (443 → WAF → backend)
// enabled=false → restore original config (443 → direct)
func switchNginxConfig(domain string, enabled bool) error {
	// Find the site config file
	siteConf := findNginxSiteConf(domain)
	if siteConf == "" {
		return nil // No nginx config found — skip silently
	}

	originals := confDir + "/nginx-originals"
	origFile := filepath.Join(originals, filepath.Base(siteConf)+".orig")

	if !enabled {
		// DISABLE: restore original config (direct serving)
		if _, err := os.Stat(origFile); err != nil {
			return fmt.Errorf("no original config to restore for %s", domain)
		}
		data, err := os.ReadFile(origFile)
		if err != nil {
			return err
		}
		if err := os.WriteFile(siteConf, data, 0o644); err != nil {
			return err
		}
	} else {
		// ENABLE: generate WAF proxy config
		if err := generateProxyConfig(domain, siteConf, origFile); err != nil {
			return err
		}
	}

	// Test and reload nginx
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		// Rollback on failure
		if !enabled {
			// Was trying to restore — put proxy config back
			_ = generateProxyConfig(domain, siteConf, origFile)
		} else if _, statErr := os.Stat(origFile); statErr == nil {
			// Was trying to proxy — restore original
			origData, _ := os.ReadFile(origFile)
			_ = os.WriteFile(siteConf, origData, 0o644)
		}
		return fmt.Errorf("nginx test failed: %s", string(out))
	}
	_ = exec.Command("systemctl", "reload", "nginx").Run()
	return nil
}

// findNginxSiteConf locates the nginx site config for a domain.
func findNginxSiteConf(domain string) string {
	// Try exact filename match first
	candidates := []string{
		"/etc/nginx/sites-available/" + domain,
		"/etc/nginx/sites-available/" + domain + ".conf",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Search all site configs for server_name
	entries, _ := os.ReadDir("/etc/nginx/sites-available")
	re := regexp.MustCompile(`server_name\s+[^;]*\b` + regexp.QuoteMeta(domain) + `\b`)
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".orig") || strings.HasSuffix(e.Name(), ".pre-waf") {
			continue
		}
		path := "/etc/nginx/sites-available/" + e.Name()
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if re.Match(data) {
			return path
		}
	}
	return ""
}

// generateProxyConfig creates a WAF proxy nginx config for a domain.
func generateProxyConfig(domain, siteConf, origFile string) error {
	// Read original to extract SSL paths
	origData, err := os.ReadFile(origFile)
	if err != nil {
		return fmt.Errorf("cannot read original config: %w", err)
	}

	sslCert := extractNginxDirective(string(origData), "ssl_certificate")
	sslKey := extractNginxDirective(string(origData), "ssl_certificate_key")
	if sslCert == "" || sslKey == "" {
		return fmt.Errorf("no SSL certs found in original config for %s", domain)
	}

	sslInclude := extractNginxDirective(string(origData), "include.*options-ssl")
	sslDhparam := extractNginxDirective(string(origData), "ssl_dhparam")

	var sb strings.Builder
	sb.WriteString("# AXCerberus WAF Frontend — auto-generated\n")
	sb.WriteString("server {\n")
	sb.WriteString(fmt.Sprintf("    server_name %s;\n", domain))
	sb.WriteString("    listen 443 ssl;\n")
	sb.WriteString(fmt.Sprintf("    ssl_certificate %s;\n", sslCert))
	sb.WriteString(fmt.Sprintf("    ssl_certificate_key %s;\n", sslKey))
	if sslInclude != "" {
		sb.WriteString(fmt.Sprintf("    include %s;\n", sslInclude))
	}
	if sslDhparam != "" {
		sb.WriteString(fmt.Sprintf("    ssl_dhparam %s;\n", sslDhparam))
	}
	sb.WriteString("\n    location / {\n")
	wafListen := getConfigKey("listen")
	if wafListen == "" {
		wafListen = "127.0.0.1:8080"
	}
	sb.WriteString(fmt.Sprintf("        proxy_pass http://%s;\n", wafListen))
	sb.WriteString("        proxy_set_header Host $host;\n")
	sb.WriteString("        proxy_set_header X-Real-IP $remote_addr;\n")
	sb.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n")
	sb.WriteString("        proxy_set_header X-Forwarded-Proto https;\n")
	sb.WriteString("        proxy_http_version 1.1;\n")
	sb.WriteString("        proxy_set_header Connection \"\";\n")
	sb.WriteString("        proxy_connect_timeout 10s;\n")
	sb.WriteString("        proxy_read_timeout 60s;\n")
	sb.WriteString("        proxy_send_timeout 60s;\n")
	sb.WriteString("    }\n}\n")
	sb.WriteString("server {\n")
	sb.WriteString("    listen 80;\n")
	sb.WriteString(fmt.Sprintf("    server_name %s;\n", domain))
	sb.WriteString("    return 301 https://$host$request_uri;\n")
	sb.WriteString("}\n")

	return os.WriteFile(siteConf, []byte(sb.String()), 0o644)
}

// extractNginxDirective extracts the value of a directive from nginx config text.
func extractNginxDirective(conf, directive string) string {
	re := regexp.MustCompile(`(?m)^\s*` + directive + `\s+([^;]+);`)
	m := re.FindStringSubmatch(conf)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

