package main

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// manifestInfo 是测试侧对 info.json 的最小解码形状。
type manifestInfo struct {
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	Capabilities       []string          `json:"capabilities"`
	MethodCapabilities map[string]string `json:"method_capabilities"`
}

// kernelMethodActionPattern 与内核 internal/core/registry 的 methodActionPattern
// 保持一致：动作段只能是小写字母开头的字母数字，或点分多段（不允许下划线）。
var kernelMethodActionPattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)*$`)

// privilegedCapabilities 是内核认识的 6 项特权能力。
var privilegedCapabilities = map[string]bool{
	"system:read": true, "system:admin": true,
	"net:read": true, "net:write": true,
	"proc:read": true, "proc:write": true,
}

// readManifest 读取当前仓库的 info.json 与 manifest.json。
func readManifest(t *testing.T) (manifestInfo, manifestInfo) {
	t.Helper()
	read := func(path string) manifestInfo {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读 %s: %v", path, err)
		}
		var info manifestInfo
		if err := json.Unmarshal(data, &info); err != nil {
			t.Fatalf("解析 %s: %v", path, err)
		}
		return info
	}
	return read("info.json"), read("manifest.json")
}

// TestMethodCapabilitiesDeclared 校验方法级 capability 的语法、取值、覆盖与预期一致。
//
// 覆盖范围说明：check / status / verify_file 为 system:read，baseline 为 system:admin；
// 新增的 baseline.list / schedule.get 为 read，schedule.set 为 admin。
// verify_file 因内核 methodActionPattern 不允许下划线而无法出现在 method_capabilities，
// 其有效能力由插件级 capabilities=system:read 兜底（见 TestVerifyFileFallsBackToRead）。
func TestMethodCapabilitiesDeclared(t *testing.T) {
	info, manifest := readManifest(t)
	if info.ID != "integrity" {
		t.Fatalf("info.json.id=%q", info.ID)
	}
	if info.Version != manifest.Version {
		t.Fatalf("info.json.version=%q 与 manifest.json.version=%q 不一致", info.Version, manifest.Version)
	}
	if len(info.Capabilities) != 1 || info.Capabilities[0] != "system:read" {
		t.Fatalf("插件级 capabilities=%v，期望仅 system:read（方法级再覆盖 admin）", info.Capabilities)
	}
	if len(info.MethodCapabilities) == 0 || len(info.MethodCapabilities) > 64 {
		t.Fatalf("method_capabilities 条数=%d，期望 1..64", len(info.MethodCapabilities))
	}
	want := map[string]string{
		"integrity.baseline":      "system:admin",
		"integrity.baseline.list": "system:read",
		"integrity.check":         "system:read",
		"integrity.status":        "system:read",
		"integrity.schedule.set":  "system:admin",
		"integrity.schedule.get":  "system:read",
	}
	for method, capability := range want {
		got, ok := info.MethodCapabilities[method]
		if !ok {
			t.Errorf("缺少方法级声明 %s", method)
			continue
		}
		if got != capability {
			t.Errorf("%s=%q，期望 %q", method, got, capability)
		}
	}
	for method, capability := range info.MethodCapabilities {
		action, ok := cutDomain(method, "integrity.")
		if !ok {
			t.Errorf("method_capabilities 键 %q 必须以 integrity. 为域", method)
			continue
		}
		if !kernelMethodActionPattern.MatchString(action) {
			t.Errorf("method_capabilities 键 %q 的动作段 %q 不匹配内核 methodActionPattern", method, action)
		}
		if !privilegedCapabilities[capability] {
			t.Errorf("method_capabilities[%q]=%q 不是 6 项特权能力之一", method, capability)
		}
		if _, accepted := businessVerb(method, "integrity"); !accepted {
			t.Errorf("method_capabilities 键 %q 未在 businessVerb 注册（声明了不存在的方法）", method)
		}
	}
	// 当前没有 config 契约：不应出现 config.* 的方法级声明。
	for _, method := range []string{"integrity.config.get", "integrity.config.set"} {
		if _, ok := info.MethodCapabilities[method]; ok {
			t.Errorf("尚无 config 契约，不应声明 %s", method)
		}
	}
}

// TestVerifyFileFallsBackToRead 说明并锁定 verify_file 的兜底能力：
// 内核方法级键不允许下划线，因此 verify_file 不在表内，回退到插件级 system:read。
func TestVerifyFileFallsBackToRead(t *testing.T) {
	info, _ := readManifest(t)
	if _, declared := info.MethodCapabilities["integrity.verify_file"]; declared {
		t.Fatal("integrity.verify_file 不应出现在 method_capabilities（内核 methodActionPattern 不允许下划线）")
	}
	verb, ok := businessVerb("integrity.verify_file", "integrity")
	if !ok || verb != "verify_file" {
		t.Fatalf("verify_file 必须仍被业务层接受，得到 verb=%q ok=%v", verb, ok)
	}
	if len(info.Capabilities) != 1 || info.Capabilities[0] != "system:read" {
		t.Fatalf("verify_file 的有效能力应回退到插件级 system:read，实际 capabilities=%v", info.Capabilities)
	}
}

// cutDomain 去掉插件 id 前缀。
func cutDomain(method, prefix string) (string, bool) {
	if len(method) <= len(prefix) || method[:len(prefix)] != prefix {
		return "", false
	}
	return method[len(prefix):], true
}
