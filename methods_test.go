package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// invoke 发一个请求并读回响应与 serve 结束状态（每个用例独立连接）。
func invoke(t *testing.T, method, reqID string, params json.RawMessage) *pluginapi.Response {
	t.Helper()
	pluginConn, kernelConn := net.Pipe()
	defer func() { _ = kernelConn.Close() }()
	done := startServe(pluginConn)
	writeRequest(t, kernelConn, method, reqID, params)
	response := readResponse(t, kernelConn)
	writeRequest(t, kernelConn, "kore.shutdown", "r-shutdown", nil)
	if shutdown := readResponse(t, kernelConn); string(shutdown.Result) != `{"ok":true}` {
		t.Fatalf("shutdown 结果=%s", shutdown.Result)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve 返回错误: %v", err)
	}
	return response
}

// resultString 断言无错误并返回 result 原文。
func resultString(t *testing.T, response *pluginapi.Response) string {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("意外错误: code=%s message=%s", response.Error.Code, response.Error.Message)
	}
	return string(response.Result)
}

// setupSandbox 造一个白名单根与状态目录，并把环境变量指向它们。
func setupSandbox(t *testing.T) (root, state string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "root")
	state = t.TempDir()
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("创建测试根失败: %v", err)
	}
	t.Setenv("KORE_STATE_DIR", state)
	t.Setenv("KORE_INTEGRITY_ALLOW_ROOTS", root)
	return root, state
}

// TestIntegrityMethods 覆盖四个方法经 dispatch 的完整链路与 req_id 回显。
func TestIntegrityMethods(t *testing.T) {
	root, _ := setupSandbox(t)
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("bravo"), 0o640); err != nil {
		t.Fatal(err)
	}
	rootJSON, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("baseline", func(t *testing.T) {
		response := invoke(t, "integrity.baseline", "r-1", json.RawMessage(fmt.Sprintf(`{"paths":[%s]}`, rootJSON)))
		if response.ReqID != "r-1" {
			t.Fatalf("req_id=%q，期望回显 r-1", response.ReqID)
		}
		got := resultString(t, response)
		for _, want := range []string{`"saved":true`, `"entries":2`, `"previous_entries":0`} {
			if !strings.Contains(got, want) {
				t.Fatalf("baseline result 缺少 %s: %s", want, got)
			}
		}
	})

	t.Run("check", func(t *testing.T) {
		response := invoke(t, "integrity.check", "r-2", json.RawMessage(`{}`))
		got := resultString(t, response)
		for _, want := range []string{`"ok":true`, `"unchanged":2`} {
			if !strings.Contains(got, want) {
				t.Fatalf("check result 缺少 %s: %s", want, got)
			}
		}
	})

	t.Run("status", func(t *testing.T) {
		response := invoke(t, "integrity.status", "r-3", nil)
		got := resultString(t, response)
		for _, want := range []string{`"has_baseline":true`, `"entries":2`, `"last_check_ok":true`} {
			if !strings.Contains(got, want) {
				t.Fatalf("status result 缺少 %s: %s", want, got)
			}
		}
	})

	t.Run("verify_file", func(t *testing.T) {
		content, err := os.ReadFile(filepath.Join(root, "a.txt"))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		params, err := json.Marshal(map[string]string{
			"path":            filepath.Join(root, "a.txt"),
			"expected_sha256": hex.EncodeToString(sum[:]),
		})
		if err != nil {
			t.Fatal(err)
		}
		response := invoke(t, "integrity.verify_file", "r-4", params)
		got := resultString(t, response)
		if !strings.Contains(got, `"match":true`) {
			t.Fatalf("verify_file 期望 match=true: %s", got)
		}
	})
}

// TestIntegrityInvalidParams 覆盖非法参数：缺路径、非对象、相对路径、白名单外、非规范、控制字符。
func TestIntegrityInvalidParams(t *testing.T) {
	root, _ := setupSandbox(t)
	rootJSON, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		params   json.RawMessage
		contains string
	}{
		{name: "缺少 paths", params: json.RawMessage(`{}`), contains: "paths"},
		{name: "params 非对象", params: json.RawMessage(`"x"`), contains: "params 必须是 JSON 对象"},
		{name: "相对路径", params: json.RawMessage(`{"paths":["etc/hosts"]}`), contains: "绝对路径"},
		{name: "路径穿越", params: json.RawMessage(`{"paths":["/etc/../shadow"]}`), contains: "规范"},
		{name: "白名单外", params: json.RawMessage(`{"paths":["/root/.ssh/id_rsa"]}`), contains: "白名单"},
		{name: "非规范路径", params: json.RawMessage(fmt.Sprintf(`{"paths":[%s]}`, rootJSON)), contains: ""},
		{name: "控制字符", params: json.RawMessage(`{"paths":["/etc/ho\nsts"]}`), contains: "控制字符"},
		{name: "路径条数超限", params: json.RawMessage(`{"paths":[]}`), contains: "paths"},
	}
	// 非规范路径用例：把 root 里塞双斜杠，走 E_INVALID。
	doubleSlash, err := json.Marshal(root + "//a.txt")
	if err != nil {
		t.Fatal(err)
	}
	cases[5].params = json.RawMessage(fmt.Sprintf(`{"paths":[%s]}`, doubleSlash))
	cases[5].contains = "规范"
	// 路径条数超限用例：生成 MaxPaths+1 条重复路径。
	tooMany := make([]string, 0, 257)
	for i := 0; i < 257; i++ {
		tooMany = append(tooMany, root)
	}
	tooManyJSON, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	cases[7].params = json.RawMessage(fmt.Sprintf(`{"paths":%s}`, tooManyJSON))
	cases[7].contains = "上限"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, "integrity.baseline", "r-1", tc.params)
			if response.Error == nil {
				t.Fatalf("期望 E_INVALID，实际 result=%s", response.Result)
			}
			if response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("error code=%s，期望 E_INVALID", response.Error.Code)
			}
			if tc.contains != "" && !strings.Contains(response.Error.Message, tc.contains) {
				t.Fatalf("error message=%q，期望包含 %q", response.Error.Message, tc.contains)
			}
		})
	}
}

// TestUnknownMethod 未知方法回 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	setupSandbox(t)
	response := invoke(t, "integrity.nope", "r-1", nil)
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("error=%v，期望 E_NOTFOUND", response.Error)
	}
}
