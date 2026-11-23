package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// advanceClock 让服务时钟每次调用前进 1 秒，保证快照 id / 创建时间可预测且不冲突。
func advanceClock(service *Service) {
	base := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	step := 0
	service.SetNow(func() time.Time {
		step++
		return base.Add(time.Duration(step) * time.Second)
	})
}

// TestBaselineMultiVersion 校验多版本：旧快照进入历史、列表与状态可见、说明保留。
func TestBaselineMultiVersion(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	writeTestFile(t, filepath.Join(root, "a.txt"), "v1", 0o644)

	first := mustCall[BaselineResult](t, service, "baseline",
		baselineParams{Paths: []string{root}, Note: "初始版本", Keep: 5})
	if first.ID == "" || first.ArchivedID != "" || first.BaselineCount != 1 || first.Kept != 5 {
		t.Fatalf("首份基线结果不对: %+v", first)
	}

	writeTestFile(t, filepath.Join(root, "a.txt"), "v2", 0o644)
	second := mustCall[BaselineResult](t, service, "baseline",
		baselineParams{Paths: []string{root}, Note: "发布后", Keep: 5})
	if second.PreviousEntries != 1 || second.ArchivedID != first.ID || second.BaselineCount != 2 {
		t.Fatalf("第二份基线应归档第一份: %+v", second)
	}

	listed := mustCall[BaselineListResult](t, service, "baseline.list", nil)
	if listed.Count != 2 || listed.Baselines[0].ID != second.ID || !listed.Baselines[0].Current {
		t.Fatalf("列表应最新在前且标记 current: %+v", listed)
	}
	if listed.Baselines[1].ID != first.ID || listed.Baselines[1].Current || listed.Baselines[1].Note != "初始版本" {
		t.Fatalf("历史条目不对: %+v", listed.Baselines[1])
	}

	status := mustCall[StatusResult](t, service, "status", nil)
	if !status.HasBaseline || status.BaselineCount != 2 || status.LatestID == nil ||
		*status.LatestID != second.ID || status.LatestNote == nil || *status.LatestNote != "发布后" {
		t.Fatalf("status 应报告最新与总数: %+v", status)
	}
}

// TestCheckAgainstArchivedBaseline 校验 check 可指定历史基线比对，并在该快照上回写检查时间。
func TestCheckAgainstArchivedBaseline(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	path := filepath.Join(root, "a.conf")
	writeTestFile(t, path, "one", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	writeTestFile(t, path, "two", 0o644)
	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	checked := mustCall[CheckResult](t, service, "check", checkParams{BaselineID: first.ID})
	if checked.OK || len(checked.Modified) != 1 || checked.BaselineID != first.ID {
		t.Fatalf("与旧基线比对应发现 1 处修改: %+v", checked)
	}
	if checked.Modified[0].OldSHA256 == checked.Modified[0].NewSHA256 {
		t.Fatal("old/new sha256 不应相同")
	}
	archived, err := service.store.LoadSnapshot(first.ID)
	if err != nil {
		t.Fatalf("读历史快照: %v", err)
	}
	if archived.LastCheckAt == "" || archived.LastCheckOK == nil || *archived.LastCheckOK {
		t.Fatalf("历史快照应回写 last_check 字段: %+v", archived)
	}

	latest := mustCall[CheckResult](t, service, "check", checkParams{})
	if !latest.OK || latest.BaselineID != second.ID || latest.Unchanged != 1 {
		t.Fatalf("默认应与最新基线比对: %+v", latest)
	}
}

// TestBaselineRetention 校验 keep 保留策略：只保留最近 N 份（含当前），被裁掉的 id 不可再比对。
func TestBaselineRetention(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	writeTestFile(t, filepath.Join(root, "a.txt"), "x", 0o644)
	ids := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		result := mustCall[BaselineResult](t, service, "baseline",
			baselineParams{Paths: []string{root}, Keep: 3})
		ids = append(ids, result.ID)
	}
	listed := mustCall[BaselineListResult](t, service, "baseline.list", nil)
	if listed.Count != 3 {
		t.Fatalf("keep=3 应只剩 3 份快照: %+v", listed)
	}
	current := mustCall[StatusResult](t, service, "status", nil)
	if current.BaselineCount != 3 {
		t.Fatalf("status.baseline_count=%d，期望 3", current.BaselineCount)
	}
	if _, perr := service.Call("check", json.RawMessage(`{"baseline_id":"`+ids[0]+`"}`)); perr == nil ||
		perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("已裁剪的快照应返回 E_NOTFOUND，得到 %v", perr)
	}
}

// TestBaselineKeepAndNoteValidation 校验 keep / note 边界。
func TestBaselineKeepAndNoteValidation(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "x", 0o644)
	if perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}, Keep: 101}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("keep=101 code=%s，期望 E_INVALID", perr.Code)
	}
	longNote := strings.Repeat("说", MaxNoteLen+1)
	if perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}, Note: longNote}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("超长 note code=%s，期望 E_INVALID", perr.Code)
	}
	if perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}, Note: "bad\nnote"}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("控制字符 note code=%s，期望 E_INVALID", perr.Code)
	}
	if perr := mustErr(t, service, "baseline.list", baselineListParams{Limit: MaxBaselineKeep + 1}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("limit 越界 code=%s，期望 E_INVALID", perr.Code)
	}
}

// TestCheckUnknownBaseline 校验指定不存在的基线 id 返回 E_NOTFOUND + 可操作 hint。
func TestCheckUnknownBaseline(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	perr := mustErr(t, service, "check", checkParams{BaselineID: "baseline-20000101T000000.000000000Z"})
	if perr.Code != pluginapi.E_NOTFOUND || !strings.Contains(string(perr.Detail), "baseline.list") {
		t.Fatalf("perr=%+v，期望 E_NOTFOUND + baseline.list hint", perr)
	}
}

// TestLegacyBaselineCompat 校验 0.2.0 的单文件基线（version=1、无 id/note）仍可读、可比对、可归档。
func TestLegacyBaselineCompat(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	path := filepath.Join(root, "a.txt")
	writeTestFile(t, path, "legacy", 0o644)
	created := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	raw, err := os.ReadFile(service.store.Path())
	if err != nil {
		t.Fatalf("读当前基线: %v", err)
	}
	var legacy Baseline
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatalf("解析基线: %v", err)
	}
	legacy.Version = legacyBaselineVersion
	legacy.ID = ""
	legacy.Note = ""
	payload, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("序列化旧基线: %v", err)
	}
	if err := os.WriteFile(service.store.Path(), payload, 0o600); err != nil {
		t.Fatalf("写旧基线: %v", err)
	}

	status := mustCall[StatusResult](t, service, "status", nil)
	if !status.HasBaseline || status.LatestID == nil || *status.LatestID == "" {
		t.Fatalf("旧基线应可读并派生 id: %+v", status)
	}
	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if !checked.OK || checked.BaselineID == "" {
		t.Fatalf("旧基线应可正常比对: %+v", checked)
	}

	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if second.ArchivedID == "" || second.BaselineCount != 2 {
		t.Fatalf("旧基线应被归档为历史快照: %+v", second)
	}
	if _, err := os.Stat(service.store.snapshotPath(second.ArchivedID)); err != nil {
		t.Fatalf("历史快照文件应存在: %v", err)
	}
	_ = created
}

// TestCorruptIndexFailsClosed 校验历史索引损坏时 baseline.list / 新 baseline 显式失败，不静默丢历史。
func TestCorruptIndexFailsClosed(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	writeTestFile(t, filepath.Join(root, "a.txt"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	indexPath := filepath.Join(service.store.ArchivesDir(), indexFileName)
	if err := os.WriteFile(indexPath, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("写坏索引: %v", err)
	}
	if perr := mustErr(t, service, "baseline.list", nil); perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("baseline.list code=%s，期望 E_INTERNAL", perr.Code)
	}
	if perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}}); perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("新 baseline code=%s，期望 E_INTERNAL（不静默丢历史）", perr.Code)
	}
	// 默认 check 只读当前基线，不应被索引损坏牵连。
	if checked := mustCall[CheckResult](t, service, "check", checkParams{}); !checked.OK {
		t.Fatalf("默认 check 不应受索引损坏影响: %+v", checked)
	}
}

// TestBaselineFilesAre0600 校验当前基线与历史快照均为 0600。
func TestBaselineFilesAre0600(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	writeTestFile(t, filepath.Join(root, "a.txt"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	for _, path := range []string{service.store.Path(), service.store.snapshotPath(second.ArchivedID)} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat %s: %v", path, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s 权限=%o，期望 600", path, info.Mode().Perm())
		}
	}
}
