// Package bot provides User-Agent-based bot detection and classification.
package bot

import (
	"regexp"
	"strings"
)

// Classification represents the bot classification level.
type Classification string

const (
	ClassHuman       Classification = "human"
	ClassVerifiedBot Classification = "verified_bot"
	ClassLikelyBot   Classification = "likely_bot"
	ClassSuspicious  Classification = "suspicious"
	ClassMalicious   Classification = "malicious"
)

// Result holds the result of bot detection.
type Result struct {
	IsBot          bool           `json:"is_bot"`
	Classification Classification `json:"classification"`
	BotName        string         `json:"bot_name,omitempty"`
	Score          int            `json:"score"`
}

// Detector classifies User-Agent strings.
type Detector struct {
	goodBots     []botPattern
	badBots      []botPattern
	suspPatterns []*regexp.Regexp
}

type botPattern struct {
	name    string
	pattern *regexp.Regexp
}

// NewDetector creates a bot detector with built-in patterns.
func NewDetector() *Detector {
	d := &Detector{}

	// Known good bots
	for name, pat := range map[string]string{
		"Googlebot":        `(?i)googlebot`,
		"Bingbot":          `(?i)bingbot`,
		"YandexBot":        `(?i)yandexbot`,
		"DuckDuckBot":      `(?i)duckduckbot`,
		"Baiduspider":      `(?i)baiduspider`,
		"Slurp":            `(?i)slurp`,
		"facebot":          `(?i)facebot|facebookexternalhit`,
		"Twitterbot":       `(?i)twitterbot`,
		"LinkedInBot":      `(?i)linkedinbot`,
		"Pinterest":        `(?i)pinterest`,
		"WhatsApp":         `(?i)whatsapp`,
		"Telegram":         `(?i)telegrambot`,
		"Discordbot":       `(?i)discordbot`,
		"Slackbot":         `(?i)slackbot`,
		"UptimeRobot":      `(?i)uptimerobot`,
		"Pingdom":          `(?i)pingdom`,
		"GTmetrix":         `(?i)gtmetrix`,
		"Google-PageSpeed": `(?i)google\s*page\s*speed|lighthouse`,
	} {
		d.goodBots = append(d.goodBots, botPattern{name: name, pattern: regexp.MustCompile(pat)})
	}

	// Known malicious bots / scanners
	for name, pat := range map[string]string{
		"Nikto":          `(?i)nikto`,
		"Nmap":           `(?i)nmap`,
		"Nessus":         `(?i)nessus`,
		"SQLmap":         `(?i)sqlmap`,
		"Acunetix":       `(?i)acunetix`,
		"BurpSuite":      `(?i)burpsuite|burp\s*co`,
		"Masscan":        `(?i)masscan`,
		"w3af":           `(?i)w3af`,
		"Skipfish":       `(?i)skipfish`,
		"Havij":          `(?i)havij`,
		"DirBuster":      `(?i)dirbuster`,
		"GoBuster":       `(?i)gobuster`,
		"Wfuzz":          `(?i)wfuzz`,
		"Hydra":          `(?i)hydra`,
		"Metasploit":     `(?i)metasploit`,
		"ZAProxy":        `(?i)zaproxy|owasp\s*zap`,
		"OpenVAS":        `(?i)openvas`,
		"Nuclei":         `(?i)nuclei`,
		"GoSpider":       `(?i)gospider`,
		"Arachni":        `(?i)arachni`,
		"Vega":           `(?i)vega\/`,
		"AppScan":        `(?i)appscan`,
		"Wget":           `(?i)^wget\/`,
		"curl":           `(?i)^curl\/`,
		"python-req":     `(?i)python-requests|python-urllib|python-httpx`,
		"Go-http":        `(?i)^go-http-client`,
		"Java":           `(?i)^java\/`,
		"libwww":         `(?i)libwww-perl`,
		"Scrapy":         `(?i)scrapy`,
		"PhantomJS":      `(?i)phantomjs`,
		"HeadlessChrome": `(?i)headlesschrome`,
		"Selenium":       `(?i)selenium`,
		"Puppeteer":      `(?i)puppeteer`,
		"httpie":         `(?i)httpie`,
	} {
		d.badBots = append(d.badBots, botPattern{name: name, pattern: regexp.MustCompile(pat)})
	}

	d.suspPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)bot|crawl|spider|scrape`),
		regexp.MustCompile(`(?i)fetch|index|archive`),
	}

	return d
}

// Detect analyses a User-Agent string and returns a classification.
func (d *Detector) Detect(userAgent string) Result {
	if userAgent == "" {
		return Result{IsBot: true, Classification: ClassMalicious, BotName: "empty-ua", Score: 95}
	}
	for _, bp := range d.badBots {
		if bp.pattern.MatchString(userAgent) {
			return Result{IsBot: true, Classification: ClassMalicious, BotName: bp.name, Score: 95}
		}
	}
	for _, bp := range d.goodBots {
		if bp.pattern.MatchString(userAgent) {
			return Result{IsBot: true, Classification: ClassVerifiedBot, BotName: bp.name, Score: 10}
		}
	}
	for _, pat := range d.suspPatterns {
		if pat.MatchString(userAgent) {
			return Result{IsBot: true, Classification: ClassLikelyBot, BotName: "generic-bot", Score: 60}
		}
	}
	if len(strings.TrimSpace(userAgent)) < 15 {
		return Result{IsBot: true, Classification: ClassSuspicious, BotName: "short-ua", Score: 70}
	}
	return Result{IsBot: false, Classification: ClassHuman, Score: 0}
}
