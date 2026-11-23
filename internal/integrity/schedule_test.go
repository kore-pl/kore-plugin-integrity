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

// TestScheduleSetContract 校验与 backup.schedule.set 同构的任务描述：
// created=false、task_id 空、plugin/method/schedule/timeout_s/params 齐备。
func TestScheduleSetContract(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	result := mustCall[ScheduleSetResult](t, service, "schedule.set", scheduleSetParams{
		Schedule: "0 4 * * *",
		TimeoutS: 1800,
		Paths:    []string{root},
	})
	if result.Created || result.TaskID != "" || !result.Saved || result.Hint == "" {
		t.Fatalf("插件不能创建内核任务，created/task_id 必须为 false/空: %+v", result)
	}
	next, err := time.Parse(time.RFC3339, result.NextRunAt)
	if err != nil || !next.After(time.Now()) {
		t.Fatalf("next_run_at=%q 不是未来时刻: %v", result.NextRunAt, err)
	}
	task := result.RecommendedTask
	if task.Name != "integrity-scan" || task.Plugin != "integrity" ||
		task.Method != "integrity.check" || task.Schedule != "0 4 * * *" || task.TimeoutS != 1800 {
		t.Fatalf("任务字段不对: %+v", task)
	}
	var params checkParams
	if err := json.Unmarshal(task.Params, &params); err != nil {
		t.Fatalf("任务参数不是 check 形状: %v (%s)", err, task.Params)
	}
	if len(params.Paths) != 1 || params.Paths[0] != root || params.BaselineID != "" {
		t.Fatalf("任务参数不对: %+v", params)
	}
	if _, err := os.Stat(filepath.Join(service.store.Dir(), scheduleFileName)); err != nil {
		t.Fatalf("任务描述未落盘: %v", err)
	}

	got := mustCall[ScheduleGetResult](t, service, "schedule.get", nil)
	if got.Count != 1 || got.Records[0].Name != "integrity-scan" || got.Records[0].Task.Method != "integrity.check" {
		t.Fatalf("schedule.get 结果不对: %+v", got)
	}
}

// TestScheduleSetWithArchivedBaseline 校验可把定时扫描绑定到指定历史基线。
func TestScheduleSetWithArchivedBaseline(t *testing.T) {
	service, root := newSandbox(t)
	advanceClock(service)
	writeTestFile(t, filepath.Join(root, "a.conf"), "x", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	result := mustCall[ScheduleSetResult](t, service, "schedule.set", scheduleSetParams{
		BaselineID: first.ID,
		Paths:      []string{root},
	})
	var params checkParams
	if err := json.Unmarshal(result.RecommendedTask.Params, &params); err != nil {
		t.Fatalf("解析参数: %v", err)
	}
	if params.BaselineID != first.ID {
		t.Fatalf("baseline_id 未写入任务参数: %+v", params)
	}
}

// TestScheduleSetRejects 校验定时任务参数与前置条件边界。
func TestScheduleSetRejects(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "x", 0o644)

	// 尚未建立基线：装一个每天失败的任务没有意义，提前报错。
	if perr := mustErr(t, service, "schedule.set", scheduleSetParams{Paths: []string{root}}); perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("无基线 code=%s，期望 E_NOTFOUND", perr.Code)
	}
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

	bad := []scheduleSetParams{
		{Schedule: "bad", Paths: []string{root}},
		{Schedule: "61 * * * *", Paths: []string{root}},
		{Schedule: "0 4 * *", Paths: []string{root}},
		{TimeoutS: 4000, Paths: []string{root}},
		{Paths: []string{"relative/path"}},
		{Paths: []string{"/root/forbidden"}},
		{Exclude: []string{"[bad"}, Paths: []string{root}},
	}
	for _, params := range bad {
		if perr := mustErr(t, service, "schedule.set", params); perr.Code != pluginapi.E_INVALID {
			t.Fatalf("params=%+v code=%s，期望 E_INVALID", params, perr.Code)
		}
	}
	if perr := mustErr(t, service, "schedule.set", scheduleSetParams{
		BaselineID: "baseline-20000101T000000.000000000Z", Paths: []string{root},
	}); perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("未知 baseline_id code=%s，期望 E_NOTFOUND", perr.Code)
	}
}

// TestScheduleCorruptFile 校验任务描述损坏时不静默忽略。
func TestScheduleCorruptFile(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if err := os.WriteFile(filepath.Join(service.store.Dir(), scheduleFileName), []byte("{broken"), 0o600); err != nil {
		t.Fatalf("写坏任务描述: %v", err)
	}
	for _, method := range []string{"schedule.get", "schedule.set"} {
		if perr := mustErr(t, service, method, scheduleSetParams{Paths: []string{root}}); perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("%s code=%s，期望 E_INTERNAL", method, perr.Code)
		}
	}
}

// TestCronNext 校验 5 段表达式的下次执行时间计算（本地时区）。
func TestCronNext(t *testing.T) {
	base := time.Date(2026, 11, 23, 10, 20, 30, 0, time.Local) // 周一
	cases := []struct {
		expr  string
		after time.Time
		want  string
	}{
		{"* * * * *", base, "2026-11-23T10:21:00"},
		{"0 4 * * *", base, "2026-11-24T04:00:00"},
		{"0 4 * * *", time.Date(2026, 11, 23, 3, 30, 0, 0, time.Local), "2026-11-23T04:00:00"},
		{"30 2 * * 1", base, "2026-11-30T02:30:00"},
		{"*/15 * * * *", time.Date(2026, 11, 23, 10, 16, 0, 0, time.Local), "2026-11-23T10:30:00"},
		{"0 0 1 * *", base, "2026-12-01T00:00:00"},
	}
	for _, c := range cases {
		expr, err := parseCron(c.expr)
		if err != nil {
			t.Fatalf("parseCron(%q): %v", c.expr, err)
		}
		got := expr.next(c.after)
		if got.Format("2006-01-02T15:04:05") != c.want {
			t.Fatalf("%q after %s = %s，期望 %s", c.expr, c.after.Format(time.RFC3339), got.Format(time.RFC3339), c.want)
		}
	}
}

// TestCronParseRejects 校验非法表达式逐段报错。
func TestCronParseRejects(t *testing.T) {
	bad := []string{"", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *",
		"* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "1,,2 * * * *"}
	for _, expr := range bad {
		if _, err := parseCron(expr); err == nil {
			t.Fatalf("parseCron(%q) 应失败", expr)
		}
	}
}

// TestScheduleGetUnknownName 校验按 name 查询不存在的描述返回 E_NOTFOUND。
func TestScheduleGetUnknownName(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.conf"), "x", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	perr := mustErr(t, service, "schedule.get", scheduleGetParams{Name: "absent"})
	if perr.Code != pluginapi.E_NOTFOUND || !strings.Contains(string(perr.Detail), "schedule.set") {
		t.Fatalf("perr=%+v，期望 E_NOTFOUND + schedule.set hint", perr)
	}
}
