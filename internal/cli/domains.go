// Package cli — domain management actions for Cerberus WAF.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
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
