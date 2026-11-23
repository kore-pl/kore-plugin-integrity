package fault_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// kernelMethodActionPattern 与内核 internal/core/registry 的 methodActionPattern 逐字一致
// （kernel: internal/core/registry/validate.go；SDK: pkg/pluginapi/pluginapitest/infocheck.go）。
// ADR-0047 起：段内允许下划线（camelCase | snake_case），段首仍限小写字母，连字符仍拒。
// 内核用它校验 method_capabilities 键的动作段，不匹配即整份清单 fail-closed（E_INVALID）。
var kernelMethodActionPattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]*(\.[a-z][a-zA-Z0-9_]*)*$`)

// declaredInfo 是本测试关心的 info.json 字段。
type declaredInfo struct {
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	Capabilities       []string          `json:"capabilities"`
	MethodCapabilities map[string]string `json:"method_capabilities"`
}

// readRepoManifests 读取仓库根的 info.json 与 manifest.json。
func readRepoManifests(t *testing.T) (declaredInfo, declaredInfo) {
	t.Helper()
	read := func(path string) declaredInfo {
		data, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatalf("读 %s: %v", path, err)
		}
		var info declaredInfo
		if err := json.Unmarshal(data, &info); err != nil {
			t.Fatalf("解析 %s: %v", path, err)
		}
		return info
	}
	return read("info.json"), read("manifest.json")
}

// TestMethodDeclarationDriftFault 锁定「声明面 vs dispatch 白名单」的裁决口径。
//
// 历史：dispatch 白名单有 8 个动词（businessVerb），method_capabilities 曾有 7 条，
// 差集是 integrity.verify_file——当时不是漏声明，而是**声明不出来**：内核
// methodActionPattern 不允许下划线，写进 method_capabilities 会让整份清单
// fail-closed（E_INVALID），插件直接装不上，只能回退插件级 capabilities。
//
// **熔断器已按 ADR-0047 解除**：内核接受下划线后，verify_file 必须单列
// system:read，否则只读方法仍回退到插件级最高要求（system:admin），被写进
// 写/管理类审计。本用例转为反向护栏：谁把这条声明删掉，谁就得先重新裁决
// 字符集（ADR-0047 §5 复审条件），不是改断言。
func TestMethodDeclarationDriftFault(t *testing.T) {
	info, manifest := readRepoManifests(t)

	// 前提自检（ADR-0047 已解除原熔断器）：内核接受下划线后，verify_file 必须可声明。
	// 若此断言失败，说明字符集被收回——ADR-0047 必须重新裁决，而不是沿用旧结论。
	if !kernelMethodActionPattern.MatchString("verify_file") {
		t.Fatal("前提已变：内核 methodActionPattern 不再接受下划线，ADR-0047 被收回，" +
			"需重新裁决 integrity.verify_file 的声明面")
	}

	// 差集那一项：verify_file 必须出现在声明面，且只能是只读的 system:read。
	capability, declared := info.MethodCapabilities["integrity.verify_file"]
	if !declared {
		t.Fatal("integrity.verify_file 必须单列 system:read（ADR-0047）：" +
			"未声明会回退插件级最高要求 system:admin，只读方法被计入管理类审计")
	}
	if capability != "system:read" {
		t.Fatalf("integrity.verify_file=%q，期望 system:read（该方法是只读校验）", capability)
	}

	// 已声明的每一条都必须过内核正则——否则同样是"装不上"级别的故障。
	for method := range info.MethodCapabilities {
		action, ok := strings.CutPrefix(method, info.ID+".")
		if !ok || action == "" {
			t.Errorf("method_capabilities 键 %q 必须以 %s. 为域", method, info.ID)
			continue
		}
		if !kernelMethodActionPattern.MatchString(action) {
			t.Errorf("method_capabilities 键 %q 的动作段 %q 不匹配内核 methodActionPattern，"+
				"内核加载会 E_INVALID", method, action)
		}
	}

	// verify_file 回退插件级能力：插件级必须仍有 system:read，否则该项权限不可用。
	hasRead := false
	for _, capability := range info.Capabilities {
		if capability == "system:read" {
			hasRead = true
		}
	}
	if !hasRead {
		t.Fatalf("插件级 capabilities=%v 缺 system:read，verify_file 回退后无能力可用", info.Capabilities)
	}

	// 声明面与发布清单必须版本同步（声明漂移的另一种形态：版本对不上）。
	if info.Version != manifest.Version {
		t.Fatalf("info.json.version=%q 与 manifest.json.version=%q 不一致", info.Version, manifest.Version)
	}
}
