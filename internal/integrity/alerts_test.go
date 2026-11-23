package integrity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildAlertsTable 表驱动校验告警聚合：指标、数量、严重度、顺序与 hint。
func TestBuildAlertsTable(t *testing.T) {
	modified := []ModifiedEntry{{Path: "/etc/a", OldSHA256: "a", NewSHA256: "b", Changes: []string{"sha256"}}}
	cases := []struct {
		name      string
		result    CheckResult
		truncated bool
		wantCodes []string
		wantSev   []string
		wantCount []int
	}{
		{
			name:   "无差异",
			result: CheckResult{Unchanged: 3},
		},
		{
			name:      "新增",
			result:    CheckResult{Added: []string{"/etc/new"}},
			wantCodes: []string{"file_added"},
			wantSev:   []string{SeverityWarning},
			wantCount: []int{1},
		},
		{
			name:      "删除与篡改同时出现",
			result:    CheckResult{Removed: []string{"/etc/gone"}, Modified: modified},
			wantCodes: []string{"file_removed", "file_modified"},
			wantSev:   []string{SeverityCritical, SeverityCritical},
			wantCount: []int{1, 1},
		},
		{
			name:      "扫描告警",
			result:    CheckResult{Unchanged: 1, Warnings: []string{"不可读: /etc/x"}},
			wantCodes: []string{"scan_incomplete"},
			wantSev:   []string{SeverityWarning},
			wantCount: []int{1},
		},
		{
			name:      "截断但无警告条目",
			result:    CheckResult{Unchanged: 1},
			truncated: true,
			wantCodes: []string{"scan_incomplete"},
			wantSev:   []string{SeverityWarning},
			wantCount: []int{0},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alerts := buildAlerts(c.result, c.truncated)
			if len(alerts) != len(c.wantCodes) {
				t.Fatalf("alerts=%+v，期望 %d 条", alerts, len(c.wantCodes))
			}
			for i, alert := range alerts {
				if alert.Code != c.wantCodes[i] || alert.Severity != c.wantSev[i] ||
					alert.Count != c.wantCount[i] || alert.Metric == "" || alert.Message == "" || alert.Hint == "" {
					t.Fatalf("第 %d 条 alert=%+v，期望 code=%s sev=%s count=%d",
						i, alert, c.wantCodes[i], c.wantSev[i], c.wantCount[i])
				}
			}
		})
	}
}

// TestCheckAlertsAndSummary 走真实 check：三态同时出现时告警顺序、计数与恢复指引正确。
func TestCheckAlertsAndSummary(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "mod.conf"), "before", 0o644)
	writeTestFile(t, filepath.Join(root, "gone.conf"), "bye", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	writeTestFile(t, filepath.Join(root, "mod.conf"), "after", 0o644)
	if err := os.Remove(filepath.Join(root, "gone.conf")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "new.conf"), "hello", 0o644)

	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if checked.OK {
		t.Fatalf("应检测到差异: %+v", checked)
	}
	if checked.Summary.Removed != 1 || checked.Summary.Modified != 1 || checked.Summary.Added != 1 {
		t.Fatalf("summary=%+v", checked.Summary)
	}
	if len(checked.Alerts) != 3 {
		t.Fatalf("alerts=%+v，期望 3 条", checked.Alerts)
	}
	want := []struct {
		code     string
		severity string
		metric   string
	}{
		{"file_removed", SeverityCritical, MetricRemovedFiles},
		{"file_modified", SeverityCritical, MetricModifiedFiles},
		{"file_added", SeverityWarning, MetricAddedFiles},
	}
	for i, expect := range want {
		alert := checked.Alerts[i]
		if alert.Code != expect.code || alert.Severity != expect.severity ||
			alert.Metric != expect.metric || alert.Count != 1 {
			t.Fatalf("第 %d 条 alert=%+v，期望 %+v", i, alert, expect)
		}
		if !strings.Contains(alert.Hint, "backup") {
			t.Fatalf("告警 hint 应给出 backup 跨插件指引: %q", alert.Hint)
		}
	}
	if checked.Recovery.Supported || checked.Recovery.Owner != "backup" ||
		checked.Recovery.Method != "backup.restore" || !strings.Contains(checked.Recovery.Hint, "backup") {
		t.Fatalf("恢复指引不对: %+v", checked.Recovery)
	}
	payload, err := json.Marshal(checked)
	if err != nil {
		t.Fatalf("序列化 check: %v", err)
	}
	if !strings.Contains(string(payload), `"alerts":[{"code":"file_removed"`) {
		t.Fatalf("alerts 未序列化为数组: %s", payload)
	}
}

// TestCheckNoDiffHasEmptyAlerts 校验无差异时 alerts 是空数组、恢复指引明确说"无差异"。
func TestCheckNoDiffHasEmptyAlerts(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "same", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if !checked.OK || checked.Alerts == nil || len(checked.Alerts) != 0 {
		t.Fatalf("无差异应 alerts=[]: %+v", checked)
	}
	if checked.Recovery.Supported {
		t.Fatal("本插件不应声明支持恢复")
	}
}
