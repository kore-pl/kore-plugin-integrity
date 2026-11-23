package integrity

import (
	"strings"
	"testing"
	"time"
)

// TestRestoreRecheckDetectsRemainingDiff 恢复旧基线后当前文件仍与基线不一致：
// verified=false + changes>0 + 明确提示"仍有 N 处不一致"，不允许假装恢复=干净。
func TestRestoreRecheckDetectsRemainingDiff(t *testing.T) {
	service, _, first, _ := restoreFixture(t)
	result := mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: first.ID})
	if !result.Restored {
		t.Fatalf("恢复未成功: %+v", result)
	}
	if result.Verified {
		t.Fatalf("当前文件是 v2-broken、基线是 v1，复核不应通过: %+v", result)
	}
	if result.Changes < 1 {
		t.Fatalf("复核变更数=%d，期望 ≥1", result.Changes)
	}
	if !strings.Contains(result.Message, "仍有") || !strings.Contains(result.Message, "不一致") {
		t.Fatalf("提示未说明仍有差异: %q", result.Message)
	}
	if len(result.Alerts) == 0 {
		t.Fatal("复核有差异时必须带 alerts")
	}
}

// TestRestoreRecheckClean 恢复到与当前文件一致的基线：verified=true、changes=0。
func TestRestoreRecheckClean(t *testing.T) {
	service, _, first, second := restoreFixture(t)
	// 先真实恢复到 A（当前基线变成 A），再恢复到 B；此时文件仍是 v2，与 B 一致。
	_ = mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: first.ID})
	result := mustCall[RestoreResult](t, service, "restore", restoreParams{BaselineID: second.ID})
	if !result.Restored || !result.Verified {
		t.Fatalf("恢复当前基线应复核通过: %+v", result)
	}
	if result.Changes != 0 {
		t.Fatalf("复核变更数=%d，期望 0", result.Changes)
	}
	if !strings.Contains(result.Message, "无差异") {
		t.Fatalf("提示未说明复核干净: %q", result.Message)
	}
}

// TestChangeSeverity 校验 severity 判据：系统二进制/配置 critical，普通文件 warning。
func TestChangeSeverity(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/etc/passwd", SeverityCritical},
		{"/usr/bin/nginx", SeverityCritical},
		{"/usr/sbin/sshd", SeverityCritical},
		{"/lib/systemd/system/kore.service", SeverityCritical},
		{"/boot/vmlinuz", SeverityCritical},
		{"/var/lib/kore/data.db", SeverityWarning},
		{"/home/pt/app.conf", SeverityWarning},
	}
	for _, tc := range cases {
		if got := severityOfPath(tc.path); got != tc.want {
			t.Fatalf("severityOfPath(%q)=%q，期望 %q", tc.path, got, tc.want)
		}
	}
	result := CheckResult{
		Removed:  []string{"/usr/bin/old"},
		Modified: []ModifiedEntry{{Path: "/home/pt/app.conf"}},
		Added:    []string{"/etc/new.conf"},
	}
	changes := buildChanges(result)
	if len(changes) != 3 {
		t.Fatalf("changes 条数=%d，期望 3", len(changes))
	}
	want := []struct{ typ, path, sev string }{
		{"removed", "/usr/bin/old", SeverityCritical},
		{"modified", "/home/pt/app.conf", SeverityWarning},
		{"added", "/etc/new.conf", SeverityCritical},
	}
	for i, item := range want {
		if changes[i].Type != item.typ || changes[i].Path != item.path || changes[i].Severity != item.sev {
			t.Fatalf("changes[%d]=%+v，期望 %+v", i, changes[i], item)
		}
	}
}

// TestScheduleSetShape 校验任务描述三要素 {id, schedule, next_run} 与幂等（重复 set 只留一条）。
func TestScheduleSetShape(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, root+"/a.conf", "v1", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	first := mustCall[ScheduleSetResult](t, service, "schedule.set", scheduleSetParams{Schedule: "0 4 * * *"})
	if first.ID != scheduleTaskName || first.Schedule != "0 4 * * *" || first.NextRun == "" {
		t.Fatalf("任务三要素不符: %+v", first)
	}
	if first.NextRun != first.NextRunAt {
		t.Fatalf("next_run=%q 与 next_run_at=%q 不一致", first.NextRun, first.NextRunAt)
	}
	if _, err := time.Parse(time.RFC3339, first.NextRun); err != nil {
		t.Fatalf("next_run=%q 不是 RFC3339: %v", first.NextRun, err)
	}
	// 幂等：同 schedule 重复设置只保留一条描述。
	second := mustCall[ScheduleSetResult](t, service, "schedule.set", scheduleSetParams{Schedule: "0 4 * * *"})
	if second.ID != first.ID {
		t.Fatalf("重复设置 id 变化: %q -> %q", first.ID, second.ID)
	}
	got := mustCall[ScheduleGetResult](t, service, "schedule.get", scheduleGetParams{})
	if got.Count != 1 {
		t.Fatalf("schedule.get count=%d，期望 1（幂等）", got.Count)
	}
}
