package cli

func init() {
	actions["waf.session.status"] = actionSessionStatus
}

func actionSessionStatus(_ []string) (any, error) {
	return apiGet("/api/v1/session/status")
}
