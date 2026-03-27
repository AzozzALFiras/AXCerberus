package cli

func init() {
	actions["waf.compliance.report"] = actionComplianceReport
}

func actionComplianceReport(_ []string) (any, error) {
	return apiGet("/api/v1/compliance/report")
}
