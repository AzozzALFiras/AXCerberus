// Package cli — per-domain statistics and per-domain blocking actions.
package cli

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	// Per-domain stats
	actions["waf.stats.domain_countries"] = actionDomainCountries
	actions["waf.stats.domain_timeline"] = actionDomainTimeline
	actions["waf.logs.domain_access"] = actionDomainAccessLog
	actions["waf.logs.domain_blocks"] = actionDomainBlockLog

	// Per-domain blocking
	actions["waf.domains.block_ip"] = actionDomainBlockIP
	actions["waf.domains.unblock_ip"] = actionDomainUnblockIP
	actions["waf.domains.blocked_ips"] = actionDomainBlockedIPs
	actions["waf.domains.block_country"] = actionDomainBlockCountry
	actions["waf.domains.unblock_country"] = actionDomainUnblockCountry
	actions["waf.domains.blocked_countries"] = actionDomainBlockedCountries
}

// ─── Per-domain stats ──────────────────────────────────────────────

func actionDomainCountries(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domain_countries <domain>")
	}
	return apiGet("/api/v1/stats/domain-countries?domain=" + url.QueryEscape(args[0]))
}

func actionDomainTimeline(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domain_timeline <domain>")
	}
	return apiGet("/api/v1/stats/domain-timeline?domain=" + url.QueryEscape(args[0]))
}

func actionDomainAccessLog(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domain_access <domain>")
	}
	return apiGet("/api/v1/logs/access/domain?domain=" + url.QueryEscape(args[0]) + "&limit=100")
}

func actionDomainBlockLog(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domain_blocks <domain>")
	}
	return apiGet("/api/v1/logs/blocks/domain?domain=" + url.QueryEscape(args[0]) + "&limit=100")
}

// ─── Per-domain blocking ───────────────────────────────────────────

const domainRulesDir = confDir + "/domain_rules"

type domainRules struct {
	BlockedIPs       []string `json:"blocked_ips"`
	BlockedCountries []string `json:"blocked_countries"`
}

func loadDomainRules(domain string) (*domainRules, error) {
	path := filepath.Join(domainRulesDir, domain+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &domainRules{
				BlockedIPs:       make([]string, 0),
				BlockedCountries: make([]string, 0),
			}, nil
		}
		return nil, err
	}
	var rules domainRules
	if err := json.Unmarshal(data, &rules); err != nil {
		return &domainRules{
			BlockedIPs:       make([]string, 0),
			BlockedCountries: make([]string, 0),
		}, nil
	}
	if rules.BlockedIPs == nil {
		rules.BlockedIPs = make([]string, 0)
	}
	if rules.BlockedCountries == nil {
		rules.BlockedCountries = make([]string, 0)
	}
	return &rules, nil
}

func saveDomainRules(domain string, rules *domainRules) error {
	_ = os.MkdirAll(domainRulesDir, 0o755)
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(domainRulesDir, domain+".json"), data, 0o644)
}

func actionDomainBlockIP(args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: domains.block_ip <domain> <ip>")
	}
	domain, ip := args[0], strings.TrimSpace(args[1])
	rules, err := loadDomainRules(domain)
	if err != nil {
		return nil, err
	}
	for _, existing := range rules.BlockedIPs {
		if existing == ip {
			return map[string]any{"ok": false, "reason": "already blocked"}, nil
		}
	}
	rules.BlockedIPs = append(rules.BlockedIPs, ip)
	if err := saveDomainRules(domain, rules); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "domain": domain, "ip": ip}, nil
}

func actionDomainUnblockIP(args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: domains.unblock_ip <domain> <ip>")
	}
	domain, ip := args[0], strings.TrimSpace(args[1])
	rules, err := loadDomainRules(domain)
	if err != nil {
		return nil, err
	}
	var filtered []string
	found := false
	for _, existing := range rules.BlockedIPs {
		if existing == ip {
			found = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !found {
		return map[string]any{"ok": false, "reason": "not found"}, nil
	}
	if filtered == nil {
		filtered = make([]string, 0)
	}
	rules.BlockedIPs = filtered
	if err := saveDomainRules(domain, rules); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "domain": domain, "ip": ip}, nil
}

func actionDomainBlockedIPs(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domains.blocked_ips <domain>")
	}
	rules, err := loadDomainRules(args[0])
	if err != nil {
		return nil, err
	}
	return map[string]any{"domain": args[0], "blocked_ips": rules.BlockedIPs, "count": len(rules.BlockedIPs)}, nil
}

func actionDomainBlockCountry(args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: domains.block_country <domain> <country_code>")
	}
	domain, code := args[0], strings.ToUpper(strings.TrimSpace(args[1]))
	rules, err := loadDomainRules(domain)
	if err != nil {
		return nil, err
	}
	for _, existing := range rules.BlockedCountries {
		if existing == code {
			return map[string]any{"ok": false, "reason": "already blocked"}, nil
		}
	}
	rules.BlockedCountries = append(rules.BlockedCountries, code)
	if err := saveDomainRules(domain, rules); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "domain": domain, "country": code}, nil
}

func actionDomainUnblockCountry(args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: domains.unblock_country <domain> <country_code>")
	}
	domain, code := args[0], strings.ToUpper(strings.TrimSpace(args[1]))
	rules, err := loadDomainRules(domain)
	if err != nil {
		return nil, err
	}
	var filtered []string
	found := false
	for _, existing := range rules.BlockedCountries {
		if existing == code {
			found = true
			continue
		}
		filtered = append(filtered, existing)
	}
	if !found {
		return map[string]any{"ok": false, "reason": "not found"}, nil
	}
	if filtered == nil {
		filtered = make([]string, 0)
	}
	rules.BlockedCountries = filtered
	if err := saveDomainRules(domain, rules); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "domain": domain, "country": code}, nil
}

func actionDomainBlockedCountries(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: domains.blocked_countries <domain>")
	}
	rules, err := loadDomainRules(args[0])
	if err != nil {
		return nil, err
	}
	return map[string]any{"domain": args[0], "blocked_countries": rules.BlockedCountries, "count": len(rules.BlockedCountries)}, nil
}
