package cli

func init() {
	actions["waf.anomaly.status"] = actionAnomalyStatus
}

func actionAnomalyStatus(_ []string) (any, error) {
	return apiGet("/api/v1/anomaly/status")
}
