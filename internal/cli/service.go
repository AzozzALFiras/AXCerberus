// Package cli — service lifecycle actions for Cerberus.
package cli

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

func init() {
	actions["waf.service.start"] = actionServiceStart
	actions["waf.service.stop"] = actionServiceStop
	actions["waf.service.restart"] = actionServiceRestart
	actions["waf.service.reload"] = actionServiceReload
}

// actionServiceStart starts the axcerberus systemd service.
func actionServiceStart(_ []string) (any, error) {
	return execSystemctl("start")
}

// actionServiceStop stops the axcerberus systemd service.
func actionServiceStop(_ []string) (any, error) {
	return execSystemctl("stop")
}

// actionServiceRestart restarts the axcerberus systemd service.
func actionServiceRestart(_ []string) (any, error) {
	return execSystemctl("restart")
}

// actionServiceReload sends SIGHUP to reload config without downtime.
func actionServiceReload(_ []string) (any, error) {
	// Find the PID of the running axcerberus process
	out, err := exec.Command("systemctl", "show", serviceName, "--property=MainPID", "--value").Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get service PID: %w", err)
	}
	pidStr := strings.TrimSpace(string(out))
	if pidStr == "" || pidStr == "0" {
		return nil, fmt.Errorf("service %s is not running", serviceName)
	}
	var pid int
	if _, err := fmt.Sscanf(pidStr, "%d", &pid); err != nil {
		return nil, fmt.Errorf("invalid PID %q: %w", pidStr, err)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return nil, fmt.Errorf("failed to send SIGHUP to PID %d: %w", pid, err)
	}
	return map[string]any{
		"service": serviceName,
		"action":  "reload",
		"pid":     pid,
		"ok":      true,
	}, nil
}

// execSystemctl runs a systemctl action and returns the result.
func execSystemctl(action string) (any, error) {
	cmd := exec.Command("systemctl", action, serviceName)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		return nil, fmt.Errorf("systemctl %s %s failed: %s %s", action, serviceName, err, output)
	}
	// Verify the new state
	status := "unknown"
	stOut, stErr := exec.Command("systemctl", "is-active", serviceName).Output()
	if stErr == nil {
		status = strings.TrimSpace(string(stOut))
	}
	return map[string]any{
		"service": serviceName,
		"action":  action,
		"status":  status,
		"ok":      true,
	}, nil
}
