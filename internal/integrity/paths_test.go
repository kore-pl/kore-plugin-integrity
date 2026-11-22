package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// TestAllowlistDefaults 覆盖默认白名单的放行与拒绝。
func TestAllowlistDefaults(t *testing.T) {
	allow := NewAllowlist("", nil)
	allowed := []string{"/etc", "/etc/hosts", "/usr/bin", "/usr/sbin", "/opt", "/var/www/html"}
	for _, path := range allowed {
		if _, perr := allow.Resolve(path, false); perr != nil {
			t.Fatalf("默认白名单应放行 %s: %v", path, perr.Message)
		}
	}
	rejected := []string{
		"", "etc/hosts", "/root/.ssh/id_rsa", "/home/pt/secret",
		"/etc/../shadow", "/etc//hosts", "/etc/ho\nsts", "/tmp/file",
	}
	for _, path := range rejected {
		_, perr := allow.Resolve(path, false)
		if perr == nil {
			t.Fatalf("期望拒绝路径 %q", path)
		}
		if perr.Code != pluginapi.E_INVALID {
			t.Fatalf("路径 %q 错误码=%s，期望 E_INVALID", path, perr.Code)
		}
	}
}

// TestAllowlistExtraRoots 验证 KORE_INTEGRITY_ALLOW_ROOTS 追加根生效。
func TestAllowlistExtraRoots(t *testing.T) {
	root := t.TempDir()
	allow := NewAllowlist("", []string{root})
	if _, perr := allow.Resolve(filepath.Join(root, "a.txt"), false); perr != nil {
		t.Fatalf("额外根应放行: %v", perr.Message)
	}
}

// TestParseAllowRoots 覆盖额外根解析：冒号分隔、去空白、非法输入报错。
func TestParseAllowRoots(t *testing.T) {
	roots, err := ParseAllowRoots("/etc: /opt ")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(roots) != 2 || roots[0] != "/etc" || roots[1] != "/opt" {
		t.Fatalf("roots=%v，期望 [/etc /opt]", roots)
	}
	if _, err := ParseAllowRoots("relative/path"); err == nil {
		t.Fatal("相对路径应报错")
	}
	if _, err := ParseAllowRoots("/etc/../opt"); err == nil {
		t.Fatal("非规范路径应报错")
	}
}

// TestSymlinkEscape 验证符号链接逃逸被拒、根内链接放行。
func TestSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	allow := NewAllowlist("", []string{root})
	_, perr := allow.Resolve(link, true)
	if perr == nil {
		t.Fatal("符号链接逃逸应被拒绝")
	}
	if !strings.Contains(perr.Message, "符号链接") {
		t.Fatalf("错误信息应说明符号链接逃逸: %s", perr.Message)
	}

	inside := filepath.Join(root, "real.txt")
	if err := os.WriteFile(inside, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	safeLink := filepath.Join(root, "safe")
	if err := os.Symlink(inside, safeLink); err != nil {
		t.Fatal(err)
	}
	resolved, perr := allow.Resolve(safeLink, true)
	if perr != nil {
		t.Fatalf("根内符号链接应放行: %v", perr.Message)
	}
	if resolved != inside {
		t.Fatalf("解析结果=%q，期望 %q", resolved, inside)
	}
}

// TestResolveMissing 验证不存在路径：requireExists=false 放行、true 回 E_NOTFOUND。
func TestResolveMissing(t *testing.T) {
	root := t.TempDir()
	allow := NewAllowlist("", []string{root})
	missing := filepath.Join(root, "missing.txt")
	if _, perr := allow.Resolve(missing, false); perr != nil {
		t.Fatalf("不存在的路径应允许词法通过: %v", perr.Message)
	}
	_, perr := allow.Resolve(missing, true)
	if perr == nil || perr.Code != pluginapi.E_NOTFOUND {
		t.Fatalf("requireExists=true 应回 E_NOTFOUND，实际 %v", perr)
	}
}
