package ruledsl

import (
	"fmt"
	"strings"
)

// Parse parses a DSL rule string into a Rule struct.
// Format: WHEN <conditions> THEN <action>
// Conditions are joined by AND.
//
// Examples:
//
//	WHEN path.startsWith("/api") AND method == "POST" THEN block
//	WHEN body.size > 1048576 THEN block
//	WHEN ip.in("10.0.0.0/8") THEN allow
//	WHEN path.contains(".php") AND query.contains("select") THEN block
func Parse(raw string) (Rule, error) {
	raw = strings.TrimSpace(raw)

	// Find WHEN and THEN
	upper := strings.ToUpper(raw)
	whenIdx := strings.Index(upper, "WHEN ")
	thenIdx := strings.LastIndex(upper, " THEN ")

	if whenIdx < 0 || thenIdx < 0 || thenIdx <= whenIdx {
		return Rule{}, fmt.Errorf("rule must have WHEN ... THEN ... format")
	}

	condStr := strings.TrimSpace(raw[whenIdx+5 : thenIdx])
	action := strings.TrimSpace(raw[thenIdx+6:])
	action = strings.ToLower(action)

	if action != "block" && action != "challenge" && action != "log" && action != "allow" {
		return Rule{}, fmt.Errorf("unknown action %q (use: block, challenge, log, allow)", action)
	}

	// Split conditions by AND
	parts := splitByAnd(condStr)
	conditions := make([]Condition, 0, len(parts))
	for _, part := range parts {
		cond, err := parseCondition(strings.TrimSpace(part))
		if err != nil {
			return Rule{}, fmt.Errorf("parse condition %q: %w", part, err)
		}
		conditions = append(conditions, cond)
	}

	return Rule{
		Conditions: conditions,
		Action:     action,
	}, nil
}

func splitByAnd(s string) []string {
	result := make([]string, 0, 4)
	upper := strings.ToUpper(s)
	start := 0
	for {
		idx := strings.Index(upper[start:], " AND ")
		if idx < 0 {
			result = append(result, s[start:])
			break
		}
		result = append(result, s[start:start+idx])
		start = start + idx + 5
	}
	return result
}

func parseCondition(s string) (Condition, error) {
	// Try operators in order of specificity
	operators := []struct {
		syntax   string
		operator string
	}{
		{".startsWith(", "startsWith"},
		{".contains(", "contains"},
		{".endsWith(", "endsWith"},
		{".in(", "in"},
		{" >= ", ">="},
		{" <= ", "<="},
		{" != ", "!="},
		{" == ", "=="},
		{" > ", ">"},
		{" < ", "<"},
	}

	// Method-style: field.operator("value")
	for _, op := range operators {
		if op.operator == "startsWith" || op.operator == "contains" ||
			op.operator == "endsWith" || op.operator == "in" {
			idx := strings.Index(s, op.syntax)
			if idx < 0 {
				continue
			}
			field := s[:idx]
			rest := s[idx+len(op.syntax):]
			// Remove closing paren
			rest = strings.TrimSuffix(rest, ")")
			value := unquote(rest)
			return Condition{
				Field:    field,
				Operator: op.operator,
				Value:    value,
			}, nil
		}
	}

	// Infix-style: field OP value
	for _, op := range operators {
		idx := strings.Index(s, op.syntax)
		if idx < 0 {
			continue
		}
		field := strings.TrimSpace(s[:idx])
		value := unquote(strings.TrimSpace(s[idx+len(op.syntax):]))
		return Condition{
			Field:    field,
			Operator: op.operator,
			Value:    value,
		}, nil
	}

	return Condition{}, fmt.Errorf("cannot parse condition: %s", s)
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
