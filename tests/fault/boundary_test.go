package fault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// baselineOK 执行一次基线并返回结果。
func baselineOK(t *testing.T, service *integrity.Service, paths []string) integrity.BaselineResult {
	t.Helper()
	raw, err := json.Marshal(struct {
		Paths []string `json:"paths"`
	}{Paths: paths})
	if err != nil {
		t.Fatal(err)
	}
	result, perr := service.Call("baseline", raw)
	if perr != nil {
		t.Fatalf("baseline 失败: %s %s", perr.Code, perr.Message)
	}
	return result.(integrity.BaselineResult)
}

// TestPermissionFault 权限不足的文件只跳过并记 warning，不能让整次基线失败。
func TestPermissionFault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限，跳过权限用例")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(root, "good.txt")
	bad := filepath.Join(root, "bad.txt")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, []byte("good"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o644) })

	service := integrity.NewService(state, []string{root}, integrity.DefaultLimits())
	result := baselineOK(t, service, []string{root})
	if !result.Saved || result.Entries != 1 {
		t.Fatalf("result=%+v，期望 saved=true 且只收录可读文件", result)
	}
	if !hasWarning(result.Warnings, "不可读") {
		t.Fatalf("warnings=%v，期望包含不可读", result.Warnings)
	}

	// 同族权限故障扩展到 verify_file：可读文件正常校验，
	// 不可读文件必须**显式报错**——回 match=false 会让用户以为"内容被篡改"。
	verified := callOK[integrity.VerifyFileResult](t, service, "verify_file", verifyFileRequest{
		Path: good, ExpectedSHA256: sha256Hex("good"),
	})
	if !verified.Match {
		t.Fatalf("可读文件校验 result=%+v，期望 match=true", verified)
	}
	perr := callFault(t, service, "verify_file", verifyFileRequest{
		Path: bad, ExpectedSHA256: sha256Hex("bad"),
	})
	if perr.Code != pluginapi.E_INVALID {
		t.Fatalf("不可读文件 code=%s，期望 E_INVALID（权限故障必须显式报错）", perr.Code)
	}
}

// TestOversizeFault 超大文件按上限跳过并记 warning，不失败整个调用。
func TestOversizeFault(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	service := integrity.NewService(state, []string{root}, integrity.Limits{MaxFileBytes: 4})
	result := baselineOK(t, service, []string{root})
	if !result.Saved || result.Entries != 0 {
		t.Fatalf("result=%+v，期望超大文件被跳过", result)
	}
	if !hasWarning(result.Warnings, "上限") {
		t.Fatalf("warnings=%v，期望包含上限", result.Warnings)
	}
}

// hasWarning 判定 warning 中是否有包含子串的条目。
func hasWarning(warnings []string, substring string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, substring) {
			return true
		}
	}
	return false
}
