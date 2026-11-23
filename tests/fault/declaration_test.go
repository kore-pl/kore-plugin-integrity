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
// 内核用它校验 method_capabilities 键的动作段，不匹配即整份清单 fail-closed（E_INVALID）。
var kernelMethodActionPattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*(\.[a-z][a-zA-Z0-9]*)*$`)

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
// 事实：dispatch 白名单有 8 个动词（businessVerb），method_capabilities 只有 7 条，
// 差集是 integrity.verify_file。这不是漏声明，而是**声明不出来**：
// 内核 methodActionPattern 不允许下划线，把 verify_file 写进 method_capabilities
// 会让整份清单 fail-closed（E_INVALID），插件直接装不上；缺口按设计回退插件级
// capabilities（kernel validate.go：「未声明的方法…运行期回退插件级 capabilities」）。
//
// 本用例是这条裁决的回归护栏：谁想"补齐声明"，先看它会不会把插件装崩。
func TestMethodDeclarationDriftFault(t *testing.T) {
	info, manifest := readRepoManifests(t)

	// 前提自检：一旦内核放宽了下划线，这条裁决就失效，必须重新裁决而不是沿用。
	if kernelMethodActionPattern.MatchString("verify_file") {
		t.Fatal("前提已变：内核 methodActionPattern 现在接受下划线，" +
			"需重新裁决 integrity.verify_file 是否应单列 method_capabilities 声明")
	}

	// 差集那一项：verify_file 不能出现在声明面。
	if capability, declared := info.MethodCapabilities["integrity.verify_file"]; declared {
		t.Fatalf("integrity.verify_file=%q 不能声明在 method_capabilities："+
			"动作段含下划线，内核 fail-closed 拒绝整份清单（插件装不上）", capability)
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
