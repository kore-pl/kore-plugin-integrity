package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// restoreFixture 造两份基线（A 旧、B 当前），A 已进历史，返回它们的 ID 与 A 的条目数。
func restoreFixture(t *testing.T) (*Service, string, BaselineResult, BaselineResult) {
	t.Helper()
	service, root := newSandbox(t)
	advanceClock(service)
	path := filepath.Join(root, "a.conf")
	writeTestFile(t, path, "v1", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}, Note: "good"})
	writeTestFile(t, path, "v2-broken", 0o644)
	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}, Note: "broken"})
	return service, root, first, second
}

// TestRestoreHistoryBaseline 校验恢复到历史快照：返回 from/to、当前基线切换、备份存在 0600。
func TestRestoreHistoryBaseline(t *testing.T) {
	service, _, first, second := restoreFixture(t)
	result := mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: first.ID})
	if !result.Restored || result.FromID != second.ID || result.ToID != first.ID || result.Entries != first.Entries {
		t.Fatalf("恢复结果不对: %+v", result)
	}
	current, err := service.store.Load()
	if err != nil {
		t.Fatalf("读当前基线: %v", err)
	}
	if current.ID != first.ID || current.Note != "good" {
		t.Fatalf("当前基线未切换到目标快照: %+v", current)
	}
	if result.BackupPath == "" {
		t.Fatal("恢复前必须备份当前基线")
	}
	info, err := os.Stat(result.BackupPath)
	if err != nil {
		t.Fatalf("备份文件不存在: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("备份权限=%o，期望 600", info.Mode().Perm())
	}
	payload, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatalf("读备份: %v", err)
	}
	var backup Baseline
	if err := json.Unmarshal(payload, &backup); err != nil {
		t.Fatalf("解析备份: %v", err)
	}
	if backup.ID != second.ID {
		t.Fatalf("备份内容应是被覆盖的当前基线 %s，实际 %s", second.ID, backup.ID)
	}
	// 被替换的当前基线也归档进历史，恢复后可再回滚。
	metas, err := service.store.ListSnapshots()
	if err != nil {
		t.Fatalf("列快照: %v", err)
	}
	found := false
	for _, meta := range metas {
		if meta.ID == second.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("被替换的当前基线应留在历史中: %+v", metas)
	}
}

// TestRestoreIdempotent 校验已是目标版本时 restored=false、不写盘、不新增备份。
func TestRestoreIdempotent(t *testing.T) {
	service, _, first, second := restoreFixture(t)
	if _, perr := service.Call("restore", json.RawMessage(`{"baseline_id":"`+first.ID+`"}`)); perr != nil {
		t.Fatalf("首次恢复失败: %v", perr)
	}
	before := countBackups(t, service.store.Dir())
	result := mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: first.ID})
	if result.Restored || result.FromID != first.ID || result.ToID != first.ID {
		t.Fatalf("幂等恢复结果不对: %+v", result)
	}
	if result.BackupPath != "" {
		t.Fatalf("幂等恢复不应产生新备份: %+v", result)
	}
	if after := countBackups(t, service.store.Dir()); after != before {
		t.Fatalf("幂等恢复不应新增备份文件: %d -> %d", before, after)
	}
	current, err := service.store.Load()
	if err != nil || current.ID != first.ID {
		t.Fatalf("幂等恢复不应改动当前基线: %+v err=%v", current, err)
	}
	_ = second
}

// TestRestoreNotFound 校验不存在的 id 返回 E_NOTFOUND + 可用 id hint，非法 id 返回 E_INVALID。
func TestRestoreNotFound(t *testing.T) {
	service, _, first, _ := restoreFixture(t)
	perr := mustErr(t, service, "restore", restoreParams{BaselineID: "baseline-20000101T000000.000000000Z"})
	if perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("code=%s，期望 E_NOTFOUND", perr.Code)
	}
	detail := string(perr.Detail)
	if !strings.Contains(detail, first.ID) {
		t.Fatalf("hint 应列出可用快照 id，实际 %s", detail)
	}
	for _, bad := range []string{"", "../etc", "Baseline/../x"} {
		if perr := mustErr(t, service, "restore", restoreParams{BaselineID: bad}); perr.Code != pluginapi.E_INVALID {
			t.Fatalf("id=%q code=%s，期望 E_INVALID", bad, perr.Code)
		}
	}
}

// TestRestoreWithoutCurrent 校验没有当前基线但有历史时也能恢复（from_id 为空）。
func TestRestoreWithoutCurrent(t *testing.T) {
	service, _, first, _ := restoreFixture(t)
	if err := os.Remove(service.store.Path()); err != nil {
		t.Fatalf("删除当前基线: %v", err)
	}
	result := mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: first.ID})
	if !result.Restored || result.FromID != "" || result.ToID != first.ID {
		t.Fatalf("无当前基线时恢复结果不对: %+v", result)
	}
	current, err := service.store.Load()
	if err != nil || current.ID != first.ID {
		t.Fatalf("恢复后当前基线不对: %+v err=%v", current, err)
	}
}

// countBackups 统计 <state>/baseline.bak.*.json 数量。
func countBackups(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "baseline.bak.*.json"))
	if err != nil {
		t.Fatalf("glob 备份: %v", err)
	}
	return len(matches)
}
