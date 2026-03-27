// Package cli — web server detection helpers for domain management.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// detectActiveWebServer returns the name of the running web server.
func detectActiveWebServer() string {
	for _, name := range []string{"nginx", "apache2", "httpd", "lshttpd", "lsws"} {
		out, err := exec.Command("systemctl", "is-active", name).Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return name
		}
	}
	return ""
}

// detectUpstreamPort reads the web server config to find the current listen port.
func detectUpstreamPort(ws string) int {
	switch ws {
	case "nginx":
		return detectNginxPort()
	case "apache2":
		return detectApachePort()
	case "httpd":
		return detectApachePort()
	default:
		return 0
	}
}

func detectNginxPort() int {
	listenRe := regexp.MustCompile(`listen\s+(\d+)`)
	dirs := []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"}
	for _, dir := range dirs {
		files, _ := filepath.Glob(dir + "/*")
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			matches := listenRe.FindStringSubmatch(string(data))
			if len(matches) > 1 {
				var port int
				if _, err := fmt.Sscanf(matches[1], "%d", &port); err == nil && port > 0 {
					return port
				}
			}
		}
	}
	return 80
}

func detectApachePort() int {
	for _, f := range []string{"/etc/apache2/ports.conf", "/etc/httpd/conf/httpd.conf"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		re := regexp.MustCompile(`Listen\s+(\d+)`)
		matches := re.FindStringSubmatch(string(data))
		if len(matches) > 1 {
			var port int
			if _, err := fmt.Sscanf(matches[1], "%d", &port); err == nil && port > 0 {
				return port
			}
		}
	}
	return 80
}

// detectServerDomains scans web server configs for domain names.
func detectServerDomains() []DomainInfo {
	ws := detectActiveWebServer()
	if ws == "" {
		return make([]DomainInfo, 0)
	}

	var domains []DomainInfo
	seen := make(map[string]bool)

	switch ws {
	case "nginx":
		domains = detectNginxDomains(ws, seen)
	case "apache2", "httpd":
		domains = detectApacheDomains(ws, seen)
	}

	if domains == nil {
		return make([]DomainInfo, 0)
	}
	return domains
}

func detectNginxDomains(ws string, seen map[string]bool) []DomainInfo {
	serverNameRe := regexp.MustCompile(`server_name\s+([^;]+);`)
	dirs := []string{"/etc/nginx/sites-enabled", "/etc/nginx/conf.d"}
	var result []DomainInfo

	for _, dir := range dirs {
		files, _ := filepath.Glob(dir + "/*")
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			matches := serverNameRe.FindAllStringSubmatch(string(data), -1)
			for _, m := range matches {
				for _, name := range strings.Fields(m[1]) {
					name = strings.TrimSpace(name)
					if name == "_" || name == "localhost" || name == "" {
						continue
					}
					if !seen[name] {
						seen[name] = true
						result = append(result, DomainInfo{
							Domain:    name,
							Enabled:   true,
							WebServer: ws,
						})
					}
				}
			}
		}
	}
	return result
}

func detectApacheDomains(ws string, seen map[string]bool) []DomainInfo {
	serverNameRe := regexp.MustCompile(`(?i)ServerName\s+(\S+)`)
	dirs := []string{"/etc/apache2/sites-enabled", "/etc/httpd/conf.d"}
	var result []DomainInfo

	for _, dir := range dirs {
		files, _ := filepath.Glob(dir + "/*")
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			matches := serverNameRe.FindAllStringSubmatch(string(data), -1)
			for _, m := range matches {
				name := strings.TrimSpace(m[1])
				if name == "" || name == "localhost" {
					continue
				}
				if !seen[name] {
					seen[name] = true
					result = append(result, DomainInfo{
						Domain:    name,
						Enabled:   true,
						WebServer: ws,
					})
				}
			}
		}
	}
	return result
}
