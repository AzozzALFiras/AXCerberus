package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"axcerberus/internal/vpatch"
)

const vpatchFile = "/etc/aevonx/plugins/axcerberus/vpatches.json"

func init() {
	actions["waf.vpatch.list"] = actionVPatchList
	actions["waf.vpatch.apply"] = actionVPatchApply
	actions["waf.vpatch.remove"] = actionVPatchRemove
}

func actionVPatchList(_ []string) (any, error) {
	engine := vpatch.New(vpatchFile)
	patches := engine.ListPatches()
	return map[string]any{
		"patches": patches,
		"count":   len(patches),
	}, nil
}

func actionVPatchApply(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: waf.vpatch.apply <json>")
	}
	var p vpatch.Patch
	if err := json.Unmarshal([]byte(args[0]), &p); err != nil {
		return nil, fmt.Errorf("invalid patch JSON: %w", err)
	}
	if p.ID == "" {
		p.ID = fmt.Sprintf("vp_%d", time.Now().UnixNano())
	}

	engine := vpatch.New(vpatchFile)
	if err := engine.AddPatch(p); err != nil {
		return nil, fmt.Errorf("apply patch: %w", err)
	}
	return map[string]any{"ok": true, "id": p.ID, "cve": p.CVE}, nil
}

func actionVPatchRemove(args []string) (any, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("usage: waf.vpatch.remove <id>")
	}
	engine := vpatch.New(vpatchFile)
	removed := engine.RemovePatch(args[0])
	if !removed {
		return nil, fmt.Errorf("patch %q not found", args[0])
	}
	return map[string]any{"ok": true, "removed": args[0]}, nil
}

