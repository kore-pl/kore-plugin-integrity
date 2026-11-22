package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// newSandbox 构造隔离的状态目录与该状态目录之外的扫描根。
func newSandbox(t *testing.T) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	return NewService(state, []string{root}, DefaultLimits()), root
}

// mustCall 调用方法并断言成功，返回具体结果类型。
func mustCall[T any](t *testing.T, service *Service, method string, params any) T {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	result, perr := service.Call(method, raw)
	if perr != nil {
		t.Fatalf("%s 失败: code=%s message=%s", method, perr.Code, perr.Message)
	}
	typed, ok := result.(T)
	if !ok {
		t.Fatalf("%s 结果类型 %T 不是期望类型", method, result)
	}
	return typed
}

// mustErr 调用方法并断言失败，返回错误体。
func mustErr(t *testing.T, service *Service, method string, params any) *pluginapi.Error {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	result, perr := service.Call(method, raw)
	if perr == nil {
		t.Fatalf("%s 期望失败，实际 result=%v", method, result)
	}
	return perr
}

// TestCheckNoBaseline 无基线时 check 回 E_NOTFOUND 并带 hint。
func TestCheckNoBaseline(t *testing.T) {
	service, _ := newSandbox(t)
	perr := mustErr(t, service, "check", checkParams{})
	if perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("code=%s，期望 E_NOTFOUND", perr.Code)
	}
	if !strings.Contains(string(perr.Detail), "integrity.baseline") {
		t.Fatalf("detail=%s，期望包含 hint 先建立基线", perr.Detail)
	}
}

// TestStatusNoBaseline 无基线时 status 返回 has_baseline=false 且时间字段为 null。
func TestStatusNoBaseline(t *testing.T) {
	service, _ := newSandbox(t)
	status := mustCall[StatusResult](t, service, "status", nil)
	if status.HasBaseline || status.CreatedAt != nil || status.LastCheckAt != nil || status.LastCheckOK != nil {
		t.Fatalf("无基线 status 不应有元信息: %+v", status)
	}
}

// TestBaselineAndUnchanged 三文件建基线后 check，ok=true 且 unchanged=3。
func TestBaselineAndUnchanged(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "alpha", 0o644)
	writeTestFile(t, filepath.Join(root, "b.txt"), "bravo", 0o644)
	writeTestFile(t, filepath.Join(root, "c.txt"), "charlie", 0o644)

	baseline := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if !baseline.Saved || baseline.Entries != 3 || baseline.PreviousEntries != 0 {
		t.Fatalf("baseline=%+v，期望 saved/3/0", baseline)
	}
	if baseline.TotalBytes != int64(len("alpha")+len("bravo")+len("charlie")) {
		t.Fatalf("total_bytes=%d", baseline.TotalBytes)
	}
	checked := mustCall[CheckResult](t, service, "check", checkParams{})
	if !checked.OK || checked.Unchanged != 3 {
		t.Fatalf("check=%+v，期望 ok=true unchanged=3", checked)
	}
	if len(checked.Added) != 0 || len(checked.Removed) != 0 || len(checked.Modified) != 0 {
		t.Fatalf("无变更时不应有三态条目: %+v", checked)
	}
}

// TestCheckModifiedAll 三种变更的独立判定：sha256、mode、removed、added。
func TestCheckModifiedAll(t *testing.T) {
	t.Run("sha256", func(t *testing.T) {
		service, root := newSandbox(t)
		path := filepath.Join(root, "a.txt")
		writeTestFile(t, path, "before", 0o644)
		mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

		writeTestFile(t, path, "after", 0o644)
		checked := mustCall[CheckResult](t, service, "check", checkParams{})
		if checked.OK || len(checked.Modified) != 1 {
			t.Fatalf("check=%+v，期望 modified=1 且 ok=false", checked)
		}
		modified := checked.Modified[0]
		if len(modified.Changes) != 1 || modified.Changes[0] != "sha256" {
			t.Fatalf("changes=%v，期望 [sha256]", modified.Changes)
		}
		if modified.OldSHA256 == modified.NewSHA256 {
			t.Fatal("修改前后 sha256 不应相同")
		}
	})

	t.Run("mode", func(t *testing.T) {
		service, root := newSandbox(t)
		path := filepath.Join(root, "a.txt")
		writeTestFile(t, path, "same", 0o644)
		mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		checked := mustCall[CheckResult](t, service, "check", checkParams{})
		if len(checked.Modified) != 1 {
			t.Fatalf("check=%+v，期望 modified=1", checked)
		}
		modified := checked.Modified[0]
		if len(modified.Changes) != 1 || modified.Changes[0] != "mode" {
			t.Fatalf("changes=%v，期望 [mode]", modified.Changes)
		}
		if modified.OldMode != "0644" || modified.NewMode != "0600" {
			t.Fatalf("old/new mode=%s/%s，期望 0644/0600", modified.OldMode, modified.NewMode)
		}
	})

	t.Run("removed", func(t *testing.T) {
		service, root := newSandbox(t)
		path := filepath.Join(root, "gone.txt")
		writeTestFile(t, path, "bye", 0o644)
		writeTestFile(t, filepath.Join(root, "stay.txt"), "hi", 0o644)
		mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})

		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		checked := mustCall[CheckResult](t, service, "check", checkParams{})
		if checked.OK || len(checked.Removed) != 1 || checked.Removed[0] != path {
			t.Fatalf("check=%+v，期望 removed=[%s]", checked, path)
		}
		if checked.Unchanged != 1 {
			t.Fatalf("unchanged=%d，期望 1", checked.Unchanged)
		}
	})

	t.Run("added", func(t *testing.T) {
		service, root := newSandbox(t)
		mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
		path := filepath.Join(root, "new.txt")
		writeTestFile(t, path, "new", 0o644)

		checked := mustCall[CheckResult](t, service, "check", checkParams{})
		if checked.OK || len(checked.Added) != 1 || checked.Added[0] != path {
			t.Fatalf("check=%+v，期望 added=[%s]", checked, path)
		}
	})
}

// TestBaselineOverwrite 验证基线是快照语义：再次 baseline 覆盖并回报上一版条目数。
func TestBaselineOverwrite(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "alpha", 0o644)
	first := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if first.Entries != 1 || first.PreviousEntries != 0 {
		t.Fatalf("first=%+v", first)
	}

	writeTestFile(t, filepath.Join(root, "b.txt"), "bravo", 0o644)
	second := mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if second.Entries != 2 || second.PreviousEntries != 1 {
		t.Fatalf("second=%+v，期望 entries=2 previous_entries=1", second)
	}
}

// TestStatusAfterCheck 验证 status 暴露基线元信息与最近一次检查结论。
func TestStatusAfterCheck(t *testing.T) {
	service, root := newSandbox(t)
	writeTestFile(t, filepath.Join(root, "a.txt"), "alpha", 0o644)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	mustCall[CheckResult](t, service, "check", checkParams{})

	status := mustCall[StatusResult](t, service, "status", nil)
	if !status.HasBaseline || status.Entries != 1 || status.CreatedAt == nil {
		t.Fatalf("status=%+v", status)
	}
	if status.LastCheckAt == nil || status.LastCheckOK == nil || !*status.LastCheckOK {
		t.Fatalf("last_check 字段缺失或不为 true: %+v", status)
	}
	if status.TotalBytes != int64(len("alpha")) {
		t.Fatalf("total_bytes=%d", status.TotalBytes)
	}
}

// TestVerifyFile 覆盖正确摘要、错误摘要、非法摘要与不存在路径。
func TestVerifyFile(t *testing.T) {
	service, root := newSandbox(t)
	path := filepath.Join(root, "a.txt")
	writeTestFile(t, path, "alpha", 0o644)
	sum := sha256.Sum256([]byte("alpha"))
	correct := hex.EncodeToString(sum[:])

	match := mustCall[VerifyFileResult](t, service, "verify_file", verifyFileParams{Path: path, ExpectedSHA256: correct})
	if !match.Match || match.ActualSHA256 != correct || match.ExpectedSHA256 != correct {
		t.Fatalf("verify_file=%+v，期望 match=true", match)
	}

	wrong := strings.Repeat("0", 64)
	miss := mustCall[VerifyFileResult](t, service, "verify_file", verifyFileParams{Path: path, ExpectedSHA256: wrong})
	if miss.Match || miss.ActualSHA256 != correct {
		t.Fatalf("verify_file=%+v，期望 match=false 且 actual 正确", miss)
	}

	// 大小写不敏感：大写摘要也应判等。
	upper := strings.ToUpper(correct)
	upperMatch := mustCall[VerifyFileResult](t, service, "verify_file", verifyFileParams{Path: path, ExpectedSHA256: upper})
	if !upperMatch.Match || upperMatch.ExpectedSHA256 != correct {
		t.Fatalf("大写摘要应归一化为小写并判等: %+v", upperMatch)
	}

	if perr := mustErr(t, service, "verify_file", verifyFileParams{Path: path, ExpectedSHA256: "xyz"}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("非法摘要 code=%s，期望 E_INVALID", perr.Code)
	}
	missingPath := filepath.Join(root, "missing.txt")
	if perr := mustErr(t, service, "verify_file", verifyFileParams{Path: missingPath, ExpectedSHA256: correct}); perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("不存在文件 code=%s，期望 E_NOTFOUND", perr.Code)
	}
	if perr := mustErr(t, service, "verify_file", verifyFileParams{Path: root, ExpectedSHA256: correct}); perr.Code != pluginapi.E_INVALID {
		t.Fatalf("目录 code=%s，期望 E_INVALID", perr.Code)
	}
}

// TestBaselineInvalidExclude 验证非法 glob 在建基线前被拒。
func TestBaselineInvalidExclude(t *testing.T) {
	service, root := newSandbox(t)
	perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}, Exclude: []string{"[bad"}})
	if perr.Code != pluginapi.E_INVALID {
		t.Fatalf("code=%s，期望 E_INVALID", perr.Code)
	}
}

// TestCorruptBaseline 验证基线文件损坏时不静默通过，而是 E_INTERNAL。
func TestCorruptBaseline(t *testing.T) {
	service, root := newSandbox(t)
	mustCall[BaselineResult](t, service, "baseline", baselineParams{Paths: []string{root}})
	if err := os.WriteFile(service.store.Path(), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"check", "status"} {
		perr := mustErr(t, service, method, checkParams{})
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("%s code=%s，期望 E_INTERNAL", method, perr.Code)
		}
	}
}

// TestStateDirMissing 状态目录未注入时返回 E_INTERNAL 且带 hint。
func TestStateDirMissing(t *testing.T) {
	service := NewService("", nil, DefaultLimits())
	perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{"/etc"}})
	if perr.Code != pluginapi.E_INTERNAL || !strings.Contains(string(perr.Detail), "KORE_STATE_DIR") {
		t.Fatalf("perr=%+v，期望 E_INTERNAL + KORE_STATE_DIR hint", perr)
	}
	if statusErr := mustErr(t, service, "status", nil); statusErr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("status code=%s，期望 E_INTERNAL", statusErr.Code)
	}
}

// TestBaselinePermissionOnState 状态目录不可写时基线保存失败回 E_INTERNAL。
func TestBaselinePermissionOnState(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录权限，跳过")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(state, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) })
	service := NewService(state, []string{root}, DefaultLimits())
	perr := mustErr(t, service, "baseline", baselineParams{Paths: []string{root}})
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("code=%s，期望 E_INTERNAL", perr.Code)
	}
}
