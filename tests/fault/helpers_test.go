package fault_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// faultFixture 是故障用例的公共夹具：一个可扫描的根目录 + 一个独立状态目录。
// 两者都用 t.TempDir()，不碰宿主真实目录（零侵入 G-31）。
type faultFixture struct {
	root    string
	state   string
	service *integrity.Service
}

// newFaultFixture 建夹具；files 是 root 下要预置的文件（内容为值）。
func newFaultFixture(t *testing.T, files map[string]string) *faultFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	state := filepath.Join(base, "state")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("建根目录: %v", err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatalf("建状态目录: %v", err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
			t.Fatalf("预置文件 %s: %v", name, err)
		}
	}
	return &faultFixture{
		root:    root,
		state:   state,
		service: integrity.NewService(state, []string{root}, integrity.DefaultLimits()),
	}
}

// mustJSON 序列化请求参数；失败说明测试自身写错，直接失败。
func mustJSON(t *testing.T, params any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("序列化参数失败: %v", err)
	}
	return raw
}

// callOK 调用业务方法并断言成功，返回指定结果类型。
func callOK[T any](t *testing.T, service *integrity.Service, method string, params any) T {
	t.Helper()
	var zero T
	result, perr := service.Call(method, mustJSON(t, params))
	if perr != nil {
		t.Fatalf("%s 期望成功，实际失败: %s %s", method, perr.Code, perr.Message)
	}
	typed, ok := result.(T)
	if !ok {
		t.Fatalf("%s 结果类型 %T 不是期望类型 %T", method, result, zero)
	}
	return typed
}

// callFault 调用业务方法并断言"显式失败且没有结果"：
// 失败必须有错误码，且不得同时回一个看起来正常的结果——那会让调用方误以为成功。
func callFault(t *testing.T, service *integrity.Service, method string, params any) *pluginapi.Error {
	t.Helper()
	result, perr := service.Call(method, mustJSON(t, params))
	if perr == nil {
		t.Fatalf("%s 期望失败，实际成功 result=%+v", method, result)
	}
	if result != nil {
		t.Fatalf("%s 失败时 result 必须为 nil，实际 %+v", method, result)
	}
	if perr.Code == "" || perr.Message == "" {
		t.Fatalf("%s 错误体不完整: code=%q message=%q", method, perr.Code, perr.Message)
	}
	return perr
}

// sha256Hex 返回内容的 sha256 十六进制摘要（测试侧独立计算，不复用被测实现）。
func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}
