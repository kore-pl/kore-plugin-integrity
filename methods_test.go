package main

import (
	"encoding/json"
	"net"
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

// TestIntegrityMethods 覆盖 baseline/verify 裸名与全名、req_id 回显与结构化结果。
func TestIntegrityMethods(t *testing.T) {
	params := json.RawMessage(`{"paths":["/etc/hosts","/opt/kore/config.yaml"]}`)
	for _, method := range []string{"baseline", "integrity.baseline", "verify", "integrity.verify"} {
		t.Run(method, func(t *testing.T) {
			response := invoke(t, method, "r-1", params)
			if response.ReqID != "r-1" {
				t.Fatalf("req_id=%q，期望回显 r-1", response.ReqID)
			}
			got := resultString(t, response)
			if !strings.Contains(got, `"scanned":false`) {
				t.Fatalf("result 应含 scanned:false（骨架口径）: %s", got)
			}
			if !strings.Contains(got, "/etc/hosts") {
				t.Fatalf("result 应含白名单路径: %s", got)
			}
		})
	}
}

// TestBaselineStableDigest 验证相同路径集合产生相同基线 id 与 sha256 占位摘要。
func TestBaselineStableDigest(t *testing.T) {
	p := baselineParams{Paths: []string{"/etc/hosts", "/opt/kore/config.yaml"}}
	first := runBaseline(p)
	second := runBaseline(p)
	if first.BaselineID != second.BaselineID {
		t.Fatalf("基线 id 不稳定: %q != %q", first.BaselineID, second.BaselineID)
	}
	if first.Count != 2 || len(first.Entries) != 2 {
		t.Fatalf("count=%d entries=%d，期望 2/2", first.Count, len(first.Entries))
	}
	for _, e := range first.Entries {
		if len(e.SHA256) != 64 {
			t.Fatalf("sha256 长度=%d，期望 64: %s", len(e.SHA256), e.SHA256)
		}
		if e.SHA256 != placeholderDigest(e.Path) {
			t.Fatalf("摘要与纯函数结果不一致: %s", e.Path)
		}
	}
}

// TestIntegrityInvalidParams 覆盖非法参数：缺路径、非对象、相对路径、路径穿越、白名单外、控制字符。
func TestIntegrityInvalidParams(t *testing.T) {
	cases := []struct {
		name     string
		params   json.RawMessage
		contains string
	}{
		{name: "缺少 paths", params: json.RawMessage(`{}`), contains: "paths"},
		{name: "params 非对象", params: json.RawMessage(`"x"`), contains: "params 必须是 JSON 对象"},
		{name: "相对路径", params: json.RawMessage(`{"paths":["etc/hosts"]}`), contains: "绝对路径"},
		{name: "路径穿越", params: json.RawMessage(`{"paths":["/etc/../shadow"]}`), contains: ".."},
		{name: "白名单外", params: json.RawMessage(`{"paths":["/home/pt/.ssh/id_rsa"]}`), contains: "白名单"},
		{name: "非规范路径", params: json.RawMessage(`{"paths":["/etc//hosts"]}`), contains: "规范"},
		{name: "控制字符", params: json.RawMessage(`{"paths":["/etc/ho\nsts"]}`), contains: "控制字符"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response := invoke(t, "integrity.baseline", "r-1", tc.params)
			if response.Error == nil {
				t.Fatalf("期望 E_INVALID，实际 result=%s", response.Result)
			}
			if response.Error.Code != pluginapi.E_INVALID {
				t.Fatalf("error code=%s，期望 E_INVALID", response.Error.Code)
			}
			if !strings.Contains(response.Error.Message, tc.contains) {
				t.Fatalf("error message=%q，期望包含 %q", response.Error.Message, tc.contains)
			}
		})
	}
}

// TestUnknownMethod 未知方法回 E_NOTFOUND。
func TestUnknownMethod(t *testing.T) {
	response := invoke(t, "integrity.nope", "r-1", nil)
	if response.Error == nil || response.Error.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("error=%v，期望 E_NOTFOUND", response.Error)
	}
}
