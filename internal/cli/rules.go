package cli

import (
	"fmt"
	"net/url"
)

func init() {
	actions["waf.rules.list"] = actionRulesList
	actions["waf.rules.add"] = actionRulesAdd
	actions["waf.rules.remove"] = actionRulesRemove
}

func actionRulesList(_ []string) (any, error) {
	return apiGet("/api/v1/rules/list")
}

func actionRulesAdd(args []string) (any, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: rules.add <id> <rule>")
	}
	id := url.QueryEscape(args[0])
	rule := url.QueryEscape(args[1])
	return apiGet("/api/v1/rules/add?id=" + id + "&rule=" + rule)
}

func actionRulesRemove(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: rules.remove <id>")
	}
	id := url.QueryEscape(args[0])
	return apiGet("/api/v1/rules/remove?id=" + id)
}
