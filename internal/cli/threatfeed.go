package cli

func init() {
	actions["waf.threatfeed.status"] = actionThreatFeedStatus
	actions["waf.threatfeed.update"] = actionThreatFeedUpdate
}

func actionThreatFeedStatus(_ []string) (any, error) {
	return apiGet("/api/v1/threatfeed/status")
}

func actionThreatFeedUpdate(_ []string) (any, error) {
	return apiGet("/api/v1/threatfeed/update")
}
