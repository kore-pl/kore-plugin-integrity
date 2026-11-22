package fault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// callErr 调用业务方法并断言失败。
func callErr(t *testing.T, service *integrity.Service, method string, params any) *pluginapi.Error {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	_, perr := service.Call(method, raw)
	if perr == nil {
		t.Fatalf("%s 期望失败", method)
	}
	return perr
}

// TestDiskFullFault 模拟磁盘满/状态目录不可写：基线保存必须失败并回 E_INTERNAL，
// 绝不能返回 saved=true 掩盖落盘失败。
func TestDiskFullFault(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录权限，跳过磁盘满用例")
	}
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(state, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(state, 0o700) })

	service := integrity.NewService(state, []string{root}, integrity.DefaultLimits())
	perr := callErr(t, service, "baseline", struct {
		Paths []string `json:"paths"`
	}{Paths: []string{root}})
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("code=%s，期望 E_INTERNAL（保存失败必须显式失败）", perr.Code)
	}
}

// TestCorruptBaselineFault 模拟基线文件被截断/写坏：check 与 status 都不得静默通过。
func TestCorruptBaselineFault(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "baseline.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	service := integrity.NewService(state, []string{root}, integrity.DefaultLimits())
	for _, method := range []string{"check", "status"} {
		perr := callErr(t, service, method, struct{}{})
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("%s code=%s，期望 E_INTERNAL", method, perr.Code)
		}
	}
}
