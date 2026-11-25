package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeSizeFile 写一份指定内容与权限的文件并返回期望字节数（避免测试里按字面量数长度）。
func writeSizeFile(t *testing.T, path, content string, mode os.FileMode) int64 {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("写文件 %s 失败: %v", path, err)
	}
	return int64(len(content))
}

// TestCheckModifiedReportsSizeDelta 验证 0.6.0 的可加性契约：modified[] 每条都带
// old_size / new_size / size_delta，且差值方向正确（改大 +、改小 −、只改权限 0）。
func TestCheckModifiedReportsSizeDelta(t *testing.T) {
	service, root := newSandbox(t)
	path := filepath.Join(root, "app.conf")
	oldSize := writeSizeFile(t, path, "alpha", 0o644) // 5 字节
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	newSize := writeSizeFile(t, path, "alpha-beta-gamma", 0o644) // 16 字节
	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if len(checked.Modified) != 1 {
		t.Fatalf("期望 1 条修改，得到 %+v", checked.Modified)
	}
	entry := checked.Modified[0]
	if entry.OldSize != oldSize || entry.NewSize != newSize || entry.SizeDelta != newSize-oldSize {
		t.Fatalf("体积字段不对: old=%d new=%d delta=%d（期望 %d/%d/%+d）",
			entry.OldSize, entry.NewSize, entry.SizeDelta, oldSize, newSize, newSize-oldSize)
	}
	if entry.SizeDelta <= 0 {
		t.Fatalf("改大后 size_delta 应为正，得到 %d", entry.SizeDelta)
	}

	// 改小：体积差必须为负，方向不能写反。
	smaller := writeSizeFile(t, path, "a", 0o644) // 1 字节
	shrunk := mustCall[CheckResult](t, service, "check", checkParams{})
	if len(shrunk.Modified) != 1 || shrunk.Modified[0].SizeDelta >= 0 ||
		shrunk.Modified[0].NewSize != smaller {
		t.Fatalf("改小后应得到负 delta: %+v", shrunk.Modified)
	}

	// 只改权限：先把内容写回基线里的样子（sha256 与体积都对上），再改权限 → delta 必须为 0
	// （不要拿 0 冒充"字段缺失"）。
	writeSizeFile(t, path, "alpha", 0o644)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("改权限失败: %v", err)
	}
	modeOnly := mustCall[CheckResult](t, service, "check", checkParams{})
	if len(modeOnly.Modified) != 1 || len(modeOnly.Modified[0].Changes) != 1 || modeOnly.Modified[0].Changes[0] != "mode" {
		t.Fatalf("期望只有 mode 变更: %+v", modeOnly.Modified)
	}
	if modeOnly.Modified[0].SizeDelta != 0 {
		t.Fatalf("只改权限时 size_delta 应为 0，得到 %d", modeOnly.Modified[0].SizeDelta)
	}
}

// TestModifiedEntryJSONContract 钉住前端消费的 JSON 键名（web/integrity.js 的
// rowsFromCheck 直接读 old_size / new_size / size_delta）。
func TestModifiedEntryJSONContract(t *testing.T) {
	payload, err := json.Marshal(ModifiedEntry{Path: "/etc/a", OldSize: 1024, NewSize: 2048, SizeDelta: 1024})
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	for _, key := range []string{"old_size", "new_size", "size_delta"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("modified 条目缺少契约键 %q: %s", key, payload)
		}
	}
}

// TestBaselineListReportsRoots 验证 baseline.list 回报真实扫描根：结果级 roots 是
// 当前基线的根；每个版本条目的 roots 随索引落盘（历史版本也留得住）。
func TestBaselineListReportsRoots(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "one", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	listed := mustCall[BaselineListResult](t, service, "baseline.list", nil)
	if len(listed.Roots) != 1 || listed.Roots[0] != root {
		t.Fatalf("结果级 roots 应为当前基线扫描根 %q，得到 %+v", root, listed.Roots)
	}
	if listed.Baselines[0].ID != second.ID || len(listed.Baselines[0].Roots) != 1 ||
		listed.Baselines[0].Roots[0] != root {
		t.Fatalf("当前版本条目应带 roots: %+v", listed.Baselines[0])
	}
	// 第一份基线已归档进历史：roots 必须从索引读回，而不是"归档就丢"。
	if listed.Baselines[1].ID != first.ID || len(listed.Baselines[1].Roots) != 1 ||
		listed.Baselines[1].Roots[0] != root {
		t.Fatalf("历史版本条目应带 roots: %+v", listed.Baselines[1])
	}

	// 序列化契约：前端读的是 baselines[].roots 与结果级 roots。
	raw, err := json.Marshal(listed)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var shape struct {
		Roots     []string `json:"roots"`
		Baselines []struct {
			Roots []string `json:"roots"`
		} `json:"baselines"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if len(shape.Roots) != 1 || len(shape.Baselines) < 2 || len(shape.Baselines[1].Roots) != 1 {
		t.Fatalf("JSON 形状不对: %s", raw)
	}
}

// TestBaselineListLegacyBaselineNoRoots 旧基线（0.2.0 的 version=1，没有 roots 字段）
// 不能让 baseline.list 崩：roots 为空数组，其余字段照常。
func TestBaselineListLegacyBaselineNoRoots(t *testing.T) {
	service, root := newSandbox(t)
	if err := os.MkdirAll(filepath.Join(service.store.Dir()), 0o700); err != nil {
		t.Fatalf("建状态目录失败: %v", err)
	}
	legacy := map[string]any{
		"version":    1,
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
		"entries": []map[string]any{{
			"path": filepath.Join(root, "a.conf"), "sha256": "deadbeef", "size": 3, "mode": "0644",
		}},
		"total_bytes": 3,
	}
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("序列化旧基线失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(service.store.Dir(), baselineFileName), payload, 0o600); err != nil {
		t.Fatalf("写旧基线失败: %v", err)
	}
	listed := mustCall[BaselineListResult](t, service, "baseline.list", nil)
	if listed.Count != 1 || listed.Baselines[0].Current != true {
		t.Fatalf("旧基线应被识别为当前基线: %+v", listed.Baselines)
	}
	if len(listed.Roots) != 0 || len(listed.Baselines[0].Roots) != 0 {
		t.Fatalf("旧基线没有 roots，应回空而不是伪造路径: %+v", listed.Roots)
	}
}

// TestStatusScanHistory 验证扫描历史：每 check 一条、最新在前、计数与结论对齐，
// 且超过 MaxScanHistory 后按上限裁剪（老的先走）。
func TestStatusScanHistory(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "one", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	empty := mustCall[StatusResult](t, service, "status", nil)
	if len(empty.ScanHistory) != 0 || empty.ScanHistory == nil {
		t.Fatalf("未扫描时应回空数组（不是 null）: %+v", empty.ScanHistory)
	}

	clean := mustCall[CheckResult](t, service, "check", checkParams{})
	if !clean.OK {
		t.Fatalf("首次扫描应无差异: %+v", clean)
	}
	writeTestFile(t, filepath.Join(root, "a.conf"), "one-changed", 0o644)
	writeTestFile(t, filepath.Join(root, "b.conf"), "new", 0o644)
	dirty := mustCall[CheckResult](t, service, "check", checkParams{})

	status := mustCall[StatusResult](t, service, "status", nil)
	if len(status.ScanHistory) != 2 {
		t.Fatalf("应有 2 条扫描历史，得到 %+v", status.ScanHistory)
	}
	newest, older := status.ScanHistory[0], status.ScanHistory[1]
	if newest.CheckedAt != dirty.CheckedAt || older.CheckedAt != clean.CheckedAt {
		t.Fatalf("顺序应最新在前: newest=%+v older=%+v", newest, older)
	}
	if newest.OK || newest.Modified != 1 || newest.Added != 1 || newest.Removed != 0 {
		t.Fatalf("最新一条计数不对: %+v", newest)
	}
	if !older.OK || older.Modified != 0 || older.Added != 0 || older.Unchanged != 1 {
		t.Fatalf("上一条计数不对: %+v", older)
	}
	if newest.BaselineID != first.ID {
		t.Fatalf("扫描历史应记录基线 id: %+v", newest)
	}

	// 触发上限：连续 check 到超过 MaxScanHistory，历史条数必须收敛在上限。
	for i := 0; i < MaxScanHistory+5; i++ {
		mustCall[CheckResult](t, service, "check", checkParams{})
	}
	capped := mustCall[StatusResult](t, service, "status", nil)
	if len(capped.ScanHistory) != MaxScanHistory {
		t.Fatalf("扫描历史应收敛到 %d 条，得到 %d", MaxScanHistory, len(capped.ScanHistory))
	}
	size, err := os.Stat(filepath.Join(service.store.Dir(), scanHistoryFileName))
	if err != nil {
		t.Fatalf("扫描历史文件应已落盘: %v", err)
	}
	if size.Size() > 16*1024 {
		t.Fatalf("扫描历史落盘 %d 字节，超出 16 KiB 预算（G-03）", size.Size())
	}
}

// TestScanHistoryCorruptSelfHeals 扫描历史是辅助轨道：文件损坏时 status 仍可用
// （回空历史），下一次 check 覆盖重写（自愈），不把基线/索引的 fail-closed 口径搬到这里。
func TestScanHistoryCorruptSelfHeals(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "one", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	mustCall[CheckResult](t, service, "check", checkParams{})

	corrupt := filepath.Join(service.store.Dir(), scanHistoryFileName)
	if err := os.WriteFile(corrupt, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("写损坏文件失败: %v", err)
	}
	status := mustCall[StatusResult](t, service, "status", nil)
	if len(status.ScanHistory) != 0 {
		t.Fatalf("损坏历史应回空而不是报错/伪造: %+v", status.ScanHistory)
	}
	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if len(checked.Warnings) != 0 {
		t.Fatalf("自愈不应产生 warning: %+v", checked.Warnings)
	}
	healed := mustCall[StatusResult](t, service, "status", nil)
	if len(healed.ScanHistory) != 1 || healed.ScanHistory[0].CheckedAt != checked.CheckedAt {
		t.Fatalf("check 后应重写一条历史: %+v", healed.ScanHistory)
	}
}
