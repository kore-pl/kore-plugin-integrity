package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestFile 写入文件并显式 chmod，避免 umask 影响 mode 断言。
func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// newTestScanner 以临时根构造扫描器。
func newTestScanner(t *testing.T, limits Limits) (*Scanner, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return NewScanner(NewAllowlist("", []string{root}), limits), root
}

// TestScanBasic 验证递归条目、sha256、mode 与元数据。
func TestScanBasic(t *testing.T) {
	scanner, root := newTestScanner(t, DefaultLimits())
	writeTestFile(t, filepath.Join(root, "a.txt"), "alpha", 0o644)
	writeTestFile(t, filepath.Join(root, "sub", "b.txt"), "bravo", 0o600)

	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries=%d，期望 2", len(result.Entries))
	}
	if result.TotalBytes != int64(len("alpha")+len("bravo")) {
		t.Fatalf("total_bytes=%d，期望 %d", result.TotalBytes, len("alpha")+len("bravo"))
	}
	byPath := map[string]Entry{}
	for _, entry := range result.Entries {
		byPath[entry.Path] = entry
	}
	entry := byPath[filepath.Join(root, "a.txt")]
	sum := sha256.Sum256([]byte("alpha"))
	if entry.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256=%s 与内容不符", entry.SHA256)
	}
	if entry.Mode != "0644" {
		t.Fatalf("mode=%s，期望 0644", entry.Mode)
	}
	if entry.Size != 5 {
		t.Fatalf("size=%d，期望 5", entry.Size)
	}
	if entry.UID != os.Getuid() || entry.GID != os.Getgid() {
		t.Fatalf("uid/gid=%d/%d，期望 %d/%d", entry.UID, entry.GID, os.Getuid(), os.Getgid())
	}
	if entry.MTime == "" {
		t.Fatal("mtime 不应为空")
	}
	if entry.SHA256 == "" || strings.Contains(entry.SHA256, " ") {
		t.Fatalf("sha256 非法: %q", entry.SHA256)
	}
}

// TestScanExcludeGlob 验证 glob 排除：按文件名与按路径前缀。
func TestScanExcludeGlob(t *testing.T) {
	scanner, root := newTestScanner(t, DefaultLimits())
	writeTestFile(t, filepath.Join(root, "keep.txt"), "keep", 0o644)
	writeTestFile(t, filepath.Join(root, "skip.log"), "skip", 0o644)
	writeTestFile(t, filepath.Join(root, "logs", "nested.log"), "skip", 0o644)

	result, perr := scanner.Scan([]string{root}, []string{"*.log"})
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 1 || result.Entries[0].Path != filepath.Join(root, "keep.txt") {
		t.Fatalf("entries=%v，期望只保留 keep.txt", result.Entries)
	}

	result, perr = scanner.Scan([]string{root}, []string{filepath.Join(root, "logs") + "/*"})
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries=%d，期望 2（保留根下两个文件）", len(result.Entries))
	}
}

// TestScanDepthLimit 验证递归深度上限触发 warning。
func TestScanDepthLimit(t *testing.T) {
	scanner, root := newTestScanner(t, Limits{MaxDepth: 2})
	deep := filepath.Join(root, "d1", "d2", "d3", "d4", "deep.txt")
	writeTestFile(t, deep, "deep", 0o644)

	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("超过深度上限的文件不应入基线: %v", result.Entries)
	}
	if !warningsContain(result.Warnings, "深度上限") {
		t.Fatalf("warnings=%v，期望包含深度上限", result.Warnings)
	}
}

// TestScanEntryLimit 验证条目上限截断。
func TestScanEntryLimit(t *testing.T) {
	scanner, root := newTestScanner(t, Limits{MaxEntries: 2})
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		writeTestFile(t, filepath.Join(root, name), "x", 0o644)
	}
	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries=%d，期望截断到 2", len(result.Entries))
	}
	if !result.Truncated {
		t.Fatal("Truncated 应为 true")
	}
	if !warningsContain(result.Warnings, "截断") {
		t.Fatalf("warnings=%v，期望包含截断", result.Warnings)
	}
}

// TestScanSkipsOversized 验证超过单文件大小上限被跳过并记 warning。
func TestScanSkipsOversized(t *testing.T) {
	scanner, root := newTestScanner(t, Limits{MaxFileBytes: 4})
	writeTestFile(t, filepath.Join(root, "big.txt"), "0123456789", 0o644)
	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("超大文件不应入基线: %v", result.Entries)
	}
	if !warningsContain(result.Warnings, "上限") {
		t.Fatalf("warnings=%v，期望包含上限", result.Warnings)
	}
}

// TestScanSkipsUnreadable 验证权限不足的文件被跳过而不是失败整个调用。
func TestScanSkipsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 无视文件权限，跳过权限用例")
	}
	scanner, root := newTestScanner(t, DefaultLimits())
	unreadable := filepath.Join(root, "secret.txt")
	writeTestFile(t, unreadable, "secret", 0o644)
	if err := os.Chmod(unreadable, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o644) })

	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("权限不足不应失败整个调用: %v", perr.Message)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("不可读文件不应入基线: %v", result.Entries)
	}
	if !warningsContain(result.Warnings, "不可读") {
		t.Fatalf("warnings=%v，期望包含不可读", result.Warnings)
	}
}

// TestScanSymlinkRules 验证符号链接：目录不跟随、根内文件入基线、越界跳过。
func TestScanSymlinkRules(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "real.txt"), "real", 0o644)
	dir := filepath.Join(root, "dir")
	writeTestFile(t, filepath.Join(dir, "inner.txt"), "inner", 0o644)
	if err := os.Symlink(dir, filepath.Join(root, "dirlink")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escapelink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "filelink")); err != nil {
		t.Fatal(err)
	}

	scanner := NewScanner(NewAllowlist("", []string{root}), DefaultLimits())
	result, perr := scanner.Scan([]string{root}, nil)
	if perr != nil {
		t.Fatalf("扫描失败: %v", perr.Message)
	}
	paths := map[string]bool{}
	for _, entry := range result.Entries {
		paths[entry.Path] = true
	}
	if !paths[filepath.Join(root, "real.txt")] || !paths[filepath.Join(dir, "inner.txt")] {
		t.Fatalf("常规文件缺失: %v", paths)
	}
	if !paths[filepath.Join(root, "filelink")] {
		t.Fatalf("根内符号链接文件应入基线: %v", paths)
	}
	if paths[filepath.Join(root, "escapelink")] {
		t.Fatalf("越界符号链接不应入基线: %v", paths)
	}
	if paths[filepath.Join(root, "dirlink")] || paths[filepath.Join(root, "dirlink", "inner.txt")] {
		t.Fatalf("符号链接目录不应被跟随: %v", paths)
	}
	if !warningsContain(result.Warnings, "符号链接目录") {
		t.Fatalf("warnings=%v，期望包含符号链接目录", result.Warnings)
	}
	if !warningsContain(result.Warnings, "越出白名单") {
		t.Fatalf("warnings=%v，期望包含越出白名单", result.Warnings)
	}
}

// TestScanMissingPath 验证不存在的路径记 warning 而不是失败。
func TestScanMissingPath(t *testing.T) {
	scanner, root := newTestScanner(t, DefaultLimits())
	result, perr := scanner.Scan([]string{filepath.Join(root, "nope")}, nil)
	if perr != nil {
		t.Fatalf("不存在的路径不应失败: %v", perr.Message)
	}
	if !warningsContain(result.Warnings, "不存在") {
		t.Fatalf("warnings=%v，期望包含不存在", result.Warnings)
	}
}

// TestScanInvalidExclude 验证非法 exclude 模式在扫描前被拒。
func TestScanInvalidExclude(t *testing.T) {
	scanner, root := newTestScanner(t, DefaultLimits())
	_, perr := scanner.Scan([]string{root}, []string{"[bad"})
	if perr == nil || perr.Code != "E_INVALID" {
		t.Fatalf("非法 exclude 期望 E_INVALID，实际 %v", perr)
	}
}

// warningsContain 判定 warning 列表中是否有包含给定子串的条目。
func warningsContain(warnings []string, substring string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, substring) {
			return true
		}
	}
	return false
}
