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
// 覆盖范围说明：check / status 为 system:read，baseline 为 system:admin；
// 新增的 baseline.list / schedule.get 为 read，schedule.set 为 admin。
// verify_file 因内核 methodActionPattern 不允许下划线而无法出现在 method_capabilities，
// 回退到插件级 capabilities（见 TestVerifyFileUndeclared）。
//
// 插件级 capabilities 必须覆盖方法级所需的最强能力（只收窄、不放大）：
// baseline / schedule.set 是 admin，因此插件级必须显式声明 system:admin，
// 否则用户在商店启用时只确认了 read，实际却有 admin 方法（能力放大，SDK 自检会拒绝）。
func TestMethodCapabilitiesDeclared(t *testing.T) {
	info, manifest := readManifest(t)
	if info.ID != "integrity" {
		t.Fatalf("info.json.id=%q", info.ID)
	}
	if info.Version != manifest.Version {
		t.Fatalf("info.json.version=%q 与 manifest.json.version=%q 不一致", info.Version, manifest.Version)
	}
	if len(info.Capabilities) != 2 || info.Capabilities[0] != "system:read" || info.Capabilities[1] != "system:admin" {
		t.Fatalf("插件级 capabilities=%v，期望 [system:read system:admin]（方法级含 admin 必须显式声明）", info.Capabilities)
	}
	if len(manifest.Capabilities) != len(info.Capabilities) {
		t.Fatalf("manifest.json capabilities=%v 与 info.json=%v 不一致", manifest.Capabilities, info.Capabilities)
	}
	for i, capability := range info.Capabilities {
		if manifest.Capabilities[i] != capability {
			t.Fatalf("manifest.json capabilities[%d]=%q 与 info.json=%q 不一致", i, manifest.Capabilities[i], capability)
		}
	}
	if len(info.MethodCapabilities) == 0 || len(info.MethodCapabilities) > 64 {
		t.Fatalf("method_capabilities 条数=%d，期望 1..64", len(info.MethodCapabilities))
	}
	want := map[string]string{
		"integrity.baseline":      "system:admin",
		"integrity.baseline.list": "system:read",
		"integrity.restore":       "system:admin",
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
		// 只收窄、不放大：方法级强度不得超过插件级同域最高声明。
		if capabilityStrength(capability) > pluginCapabilityStrength(info.Capabilities, capabilityDomain(capability)) {
			t.Errorf("method_capabilities[%q]=%q 强于插件级 capabilities=%v（能力放大，用户启用确认的范围被缩小）",
				method, capability, info.Capabilities)
		}
	}
	// 当前没有 config 契约：不应出现 config.* 的方法级声明。
	for _, method := range []string{"integrity.config.get", "integrity.config.set"} {
		if _, ok := info.MethodCapabilities[method]; ok {
			t.Errorf("尚无 config 契约，不应声明 %s", method)
		}
	}
}

// TestVerifyFileUndeclared 说明并锁定 verify_file 的兜底路径：
// 内核方法级键不允许下划线，因此 verify_file 不在表内，回退到插件级 capabilities。
// 插件级同时声明 read/admin（admin 是给 baseline/schedule.set 的），
// 所以 verify_file 不再"仅 read"；本测试只保证它仍在插件级声明域内可用。
func TestVerifyFileUndeclared(t *testing.T) {
	info, _ := readManifest(t)
	if _, declared := info.MethodCapabilities["integrity.verify_file"]; declared {
		t.Fatal("integrity.verify_file 不应出现在 method_capabilities（内核 methodActionPattern 不允许下划线）")
	}
	verb, ok := businessVerb("integrity.verify_file", "integrity")
	if !ok || verb != "verify_file" {
		t.Fatalf("verify_file 必须仍被业务层接受，得到 verb=%q ok=%v", verb, ok)
	}
	if pluginCapabilityStrength(info.Capabilities, "system") < capabilityStrength("system:read") {
		t.Fatalf("插件级 capabilities=%v 至少应包含 system:read，才能兜底 verify_file", info.Capabilities)
	}
}

// capabilityDomain 返回能力项的域（system / net / proc）。
func capabilityDomain(capability string) string {
	for i, r := range capability {
		if r == ':' {
			return capability[:i]
		}
	}
	return capability
}

// capabilityStrength 返回同域内的强度：read=1 < write=2 < admin=3；非法项返回 0。
func capabilityStrength(capability string) int {
	domain := capabilityDomain(capability)
	if len(capability) <= len(domain)+1 || capability[len(domain)] != ':' {
		return 0
	}
	switch capability[len(domain)+1:] {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	default:
		return 0
	}
}

// pluginCapabilityStrength 返回插件级在指定域的最高声明强度。
func pluginCapabilityStrength(capabilities []string, domain string) int {
	best := 0
	for _, capability := range capabilities {
		if capabilityDomain(capability) != domain {
			continue
		}
		if strength := capabilityStrength(capability); strength > best {
			best = strength
		}
	}
	return best
}

// cutDomain 去掉插件 id 前缀。
func cutDomain(method, prefix string) (string, bool) {
	if len(method) <= len(prefix) || method[:len(prefix)] != prefix {
		return "", false
	}
	return method[len(prefix):], true
}
