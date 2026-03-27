package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	backupDir = "/etc/aevonx/plugins/axcerberus/backups"
)

func init() {
	actions["waf.logs.export"] = actionLogsExport
	actions["waf.config.backup"] = actionConfigBackup
	actions["waf.config.restore"] = actionConfigRestore
	actions["waf.config.list_backups"] = actionConfigListBackups
}

// actionLogsExport exports recent logs as JSON.
func actionLogsExport(args []string) (any, error) {
	logType := "access"
	limit := 1000
	if len(args) > 0 {
		logType = args[0]
	}

	var path string
	switch logType {
	case "access":
		path = "/api/v1/logs/access"
	case "blocks":
		path = "/api/v1/logs/blocks"
	default:
		return nil, fmt.Errorf("unknown log type %q (use: access, blocks)", logType)
	}

	result, err := apiGet(fmt.Sprintf("%s?limit=%d", path, limit))
	if err != nil {
		return nil, fmt.Errorf("export logs: %w", err)
	}
	return result, nil
}

// actionConfigBackup saves a snapshot of the current config.
func actionConfigBackup(_ []string) (any, error) {
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	src, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer src.Close()

	ts := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, fmt.Sprintf("config_%s.avx", ts))
	dst, err := os.Create(backupPath)
	if err != nil {
		return nil, fmt.Errorf("create backup: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return nil, fmt.Errorf("copy config: %w", err)
	}

	return map[string]any{
		"ok":   true,
		"path": backupPath,
		"time": ts,
	}, nil
}

// actionConfigRestore restores a config from a backup.
func actionConfigRestore(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: waf.config.restore <backup_name>")
	}

	name := args[0]
	// Sanitize: only allow alphanumeric, underscore, dot
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
			return nil, fmt.Errorf("invalid backup name")
		}
	}

	backupPath := filepath.Join(backupDir, name)
	if _, err := os.Stat(backupPath); err != nil {
		return nil, fmt.Errorf("backup %q not found", name)
	}

	// Backup current config first
	ts := time.Now().Format("20060102_150405")
	preRestorePath := filepath.Join(backupDir, fmt.Sprintf("config_pre_restore_%s.avx", ts))
	if err := copyFile(configFile, preRestorePath); err != nil {
		return nil, fmt.Errorf("pre-restore backup: %w", err)
	}

	// Restore
	if err := copyFile(backupPath, configFile); err != nil {
		return nil, fmt.Errorf("restore: %w", err)
	}

	return map[string]any{
		"ok":             true,
		"restored_from":  name,
		"pre_restore":    preRestorePath,
	}, nil
}

// actionConfigListBackups lists available config backups.
func actionConfigListBackups(_ []string) (any, error) {
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{"backups": make([]any, 0), "count": 0}, nil
		}
		return nil, fmt.Errorf("list backups: %w", err)
	}

	type backup struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		ModTime string `json:"mod_time"`
	}
	backups := make([]backup, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".avx") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backup{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].ModTime > backups[j].ModTime
	})

	data, _ := json.Marshal(backups)
	var result any
	json.Unmarshal(data, &result)
	return map[string]any{"backups": result, "count": len(backups)}, nil
}

func copyFile(src, dst string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer d.Close()
	_, err = io.Copy(d, s)
	return err
}
