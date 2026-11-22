// Package integrity 实现文件完整性基线、变更比对、状态查询与单文件校验。
//
// 安全边界全部收在本文件与 scan.go：
//   - 路径词法白名单（默认 /etc、/usr/bin、/usr/sbin、/opt、/var/www、<state>，
//     其余须由 KORE_INTEGRITY_ALLOW_ROOTS 显式追加）；
//   - 符号链接二次归属：EvalSymlinks 解析后再判定真实路径是否仍在白名单根内；
//   - 递归深度 / 条目数 / 单文件大小上限，防误扫 / 扫爆；
//   - 只计算 sha256，文件内容永不进入结果。
package integrity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// DefaultRoots 是默认可扫描的宿主目录根。
var DefaultRoots = []string{"/etc", "/usr/bin", "/usr/sbin", "/opt", "/var/www"}

// Allowlist 是路径白名单：词法根 + 每个根解析符号链接后的真实根。
type Allowlist struct {
	roots     []string
	realRoots []string
}

// NewAllowlist 构造白名单：默认根 + 状态目录（绝对路径时）+ 显式追加的额外根。
// 额外根必须已由 ParseAllowRoots 校验为规范绝对路径。
func NewAllowlist(stateDir string, extra []string) *Allowlist {
	candidates := make([]string, 0, len(DefaultRoots)+len(extra)+1)
	candidates = append(candidates, DefaultRoots...)
	if stateDir != "" && filepath.IsAbs(stateDir) {
		candidates = append(candidates, stateDir)
	}
	candidates = append(candidates, extra...)
	a := &Allowlist{}
	seen := make(map[string]bool, len(candidates))
	for _, root := range candidates {
		clean := filepath.Clean(root)
		if !filepath.IsAbs(clean) || seen[clean] {
			continue
		}
		seen[clean] = true
		a.roots = append(a.roots, clean)
		real := clean
		if resolved, err := filepath.EvalSymlinks(clean); err == nil {
			real = resolved
		}
		a.realRoots = append(a.realRoots, real)
	}
	return a
}

// ParseAllowRoots 解析 KORE_INTEGRITY_ALLOW_ROOTS（冒号分隔）。
// 空串返回空列表；相对路径、非规范路径、含控制字符的条目直接报错，不静默丢弃。
func ParseAllowRoots(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, string(os.PathListSeparator))
	roots := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if hasControlRune(part) {
			return nil, errors.New("KORE_INTEGRITY_ALLOW_ROOTS 含控制字符: " + part)
		}
		if !filepath.IsAbs(part) {
			return nil, errors.New("KORE_INTEGRITY_ALLOW_ROOTS 必须是绝对路径: " + part)
		}
		clean := filepath.Clean(part)
		if clean != part {
			return nil, errors.New("KORE_INTEGRITY_ALLOW_ROOTS 必须是规范路径: " + part)
		}
		roots = append(roots, clean)
	}
	return roots, nil
}

// Roots 返回词法白名单根（副本），用于文档与调试。
func (a *Allowlist) Roots() []string {
	return append([]string(nil), a.roots...)
}

// Contains 判定已规范化的绝对路径是否落在某个白名单根内（只做词法判断）。
func (a *Allowlist) Contains(clean string) bool {
	for _, root := range a.roots {
		if within(root, clean) {
			return true
		}
	}
	return false
}

// Resolve 校验一条入参路径并返回可安全访问的路径。
//
// 词法阶段拒绝：空、相对、非规范、控制字符、白名单外。
// 解析阶段：已存在路径跟随符号链接，真实路径必须仍落在白名单内；
// 不存在的路径解析最近的已存在祖先，防止"尚不存在的路径"成为逃逸入口。
func (a *Allowlist) Resolve(raw string, requireExists bool) (string, *pluginapi.Error) {
	clean, perr := a.validateLexical(raw)
	if perr != nil {
		return "", perr
	}
	if _, err := os.Lstat(clean); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return "", invalid("路径不可访问: " + raw)
		}
		if requireExists {
			return "", notFoundErr("路径不存在: "+raw, "确认路径存在后重试")
		}
		real, resolveErr := nearestExisting(clean)
		if resolveErr != nil {
			return "", invalid("路径不可访问: " + raw)
		}
		if !a.allowsReal(real) {
			return "", invalid("路径经符号链接解析后越出白名单: " + raw)
		}
		return clean, nil
	}
	real, err := filepath.EvalSymlinks(clean)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// 悬空符号链接：目标不存在，按不存在处理。
			if requireExists {
				return "", notFoundErr("路径不存在: "+raw, "确认路径存在后重试")
			}
			return clean, nil
		}
		return "", invalid("路径不可访问: " + raw)
	}
	if !a.allowsReal(real) {
		return "", invalid("路径经符号链接解析后越出白名单: " + raw)
	}
	return real, nil
}

// ResolveExisting 校验并解析一条必须已存在的路径，语义与 kore-plugin-file 的同名函数一致：
// 先词法白名单，再跟随符号链接并二次判定归属。verify_file 等"只读单个已存在文件"的入口走这里。
func (a *Allowlist) ResolveExisting(raw string) (string, *pluginapi.Error) {
	return a.Resolve(raw, true)
}

// validateLexical 做纯词法校验，不访问文件系统。
func (a *Allowlist) validateLexical(raw string) (string, *pluginapi.Error) {
	if raw == "" {
		return "", invalid("路径不能为空")
	}
	if hasControlRune(raw) {
		return "", invalid("路径含非法控制字符: " + raw)
	}
	if !filepath.IsAbs(raw) {
		return "", invalid("路径必须是绝对路径: " + raw)
	}
	clean := filepath.Clean(raw)
	if clean != raw {
		return "", invalid("路径必须规范且不含 ..: " + raw)
	}
	if !a.Contains(clean) {
		return "", invalid("路径不在白名单内: " + raw)
	}
	return clean, nil
}

// allowsReal 判定解析后的真实路径是否落在任一白名单根的真实路径内。
func (a *Allowlist) allowsReal(real string) bool {
	for _, root := range a.realRoots {
		if within(root, real) {
			return true
		}
	}
	return false
}

// nearestExisting 自 p 向上找到第一个可解析的祖先，返回其真实路径与尚未存在的尾段拼接。
func nearestExisting(p string) (string, error) {
	cur, tail := p, ""
	for {
		real, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(real, tail), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", err
		}
		tail = filepath.Join(filepath.Base(cur), tail)
		cur = parent
	}
}

// within 判定 p 是否等于 root 或位于 root 之下（基于 filepath.Rel，避免前缀误判）。
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// hasControlRune 判定是否含 NUL / 换行等控制字符。
func hasControlRune(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// invalid 构造 E_INVALID 错误体。
func invalid(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INVALID, Message: msg}
}

// internalErr 构造 E_INTERNAL 错误体。
func internalErr(msg string) *pluginapi.Error {
	return &pluginapi.Error{Code: pluginapi.E_INTERNAL, Message: msg}
}

// notFoundErr 构造带 hint 的 E_NOTFOUND 错误体。
func notFoundErr(msg, hint string) *pluginapi.Error {
	return &pluginapi.Error{
		Code:    pluginapi.E_NOTFOUND,
		Message: msg,
		Detail:  hintDetail(hint),
	}
}
