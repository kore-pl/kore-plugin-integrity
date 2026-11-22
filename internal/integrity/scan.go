package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

const (
	// DefaultMaxDepth 是目录递归深度上限（相对于每个入参路径）。
	DefaultMaxDepth = 10
	// DefaultMaxEntries 是单次扫描的条目上限，防止误扫 / 扫爆。
	DefaultMaxEntries = 10000
	// DefaultMaxFileBytes 是单文件大小上限：8 GiB，超过即跳过并记 warning。
	DefaultMaxFileBytes int64 = 8 << 30
)

// Entry 是基线中的单条文件快照。文件内容本身永远不返回，只返回摘要与元数据。
type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	MTime  string `json:"mtime"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

// Limits 是扫描上限；零值字段回退到默认值。
type Limits struct {
	MaxDepth     int
	MaxEntries   int
	MaxFileBytes int64
}

// DefaultLimits 返回生产默认上限。
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:     DefaultMaxDepth,
		MaxEntries:   DefaultMaxEntries,
		MaxFileBytes: DefaultMaxFileBytes,
	}
}

// normalized 补齐零值字段并纠偏非法值。
func (l Limits) normalized() Limits {
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = DefaultMaxEntries
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}
	return l
}

// ScanResult 是一次扫描的产物。
type ScanResult struct {
	// Entries 按路径排序，路径唯一。
	Entries []Entry
	// TotalBytes 是成功计算摘要的文件字节数之和（不含被跳过的条目）。
	TotalBytes int64
	// Warnings 记录被跳过的条目与原因，不影响整体调用成功。
	Warnings []string
	// Truncated 表示因条目上限提前终止。
	Truncated bool
}

// Scanner 执行白名单内的递归扫描并计算 sha256。
type Scanner struct {
	allow  *Allowlist
	limits Limits
}

// NewScanner 构造扫描器。
func NewScanner(allow *Allowlist, limits Limits) *Scanner {
	return &Scanner{allow: allow, limits: limits.normalized()}
}

// Scan 扫描给定路径（文件或目录，递归）并返回快照条目。
// 单条路径必须在白名单内；路径不存在、权限不足、超大文件、越界符号链接
// 都记为 warning 并跳过，不失败整个调用——这样一条坏路径不会让整次校验无法交付。
func (s *Scanner) Scan(paths, exclude []string) (ScanResult, *pluginapi.Error) {
	pats, perr := compileExcludes(exclude)
	if perr != nil {
		return ScanResult{}, perr
	}
	var result ScanResult
	seen := make(map[string]bool)
	for _, raw := range paths {
		root, perr := s.allow.Resolve(raw, false)
		if perr != nil {
			return ScanResult{}, perr
		}
		if err := s.walk(root, 0, pats, &result, seen); err != nil {
			if errors.Is(err, errStopScan) {
				break
			}
			return ScanResult{}, internalErr("扫描失败: " + err.Error())
		}
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].Path < result.Entries[j].Path })
	return result, nil
}

// errStopScan 表示达到条目上限，提前结束扫描。
var errStopScan = errors.New("scan stopped")

// walk 递归扫描单条路径。
func (s *Scanner) walk(path string, depth int, pats []string, result *ScanResult, seen map[string]bool) error {
	if depth > s.limits.MaxDepth {
		result.Warnings = append(result.Warnings, fmt.Sprintf("达到递归深度上限 %d，跳过: %s", s.limits.MaxDepth, path))
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			result.Warnings = append(result.Warnings, "路径不存在，跳过: "+path)
			return nil
		}
		result.Warnings = append(result.Warnings, "路径不可访问，跳过: "+path)
		return nil
	}
	if matchExclude(path, pats) {
		return nil
	}
	if info.IsDir() {
		children, readErr := os.ReadDir(path)
		if readErr != nil {
			result.Warnings = append(result.Warnings, "目录不可读，跳过: "+path)
			return nil
		}
		for _, child := range children {
			childPath := filepath.Join(path, child.Name())
			if err := s.walk(childPath, depth+1, pats, result, seen); err != nil {
				return err
			}
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		real, linkErr := filepath.EvalSymlinks(path)
		if linkErr != nil {
			result.Warnings = append(result.Warnings, "符号链接不可解析，跳过: "+path)
			return nil
		}
		if !s.allow.allowsReal(real) {
			result.Warnings = append(result.Warnings, "符号链接解析后越出白名单，跳过: "+path)
			return nil
		}
		target, statErr := os.Stat(real)
		if statErr != nil {
			result.Warnings = append(result.Warnings, "符号链接目标不可访问，跳过: "+path)
			return nil
		}
		if target.IsDir() {
			// 不跟随符号链接目录：既防环，也防把挂载点外的整棵树带进基线。
			result.Warnings = append(result.Warnings, "跳过符号链接目录（不跟随）: "+path)
			return nil
		}
		return s.hashEntry(path, real, target, result, seen)
	}
	if !info.Mode().IsRegular() {
		result.Warnings = append(result.Warnings, "跳过非普通文件: "+path)
		return nil
	}
	return s.hashEntry(path, path, info, result, seen)
}

// hashEntry 计算单个文件的 sha256 并登记条目；超限或不可读时记 warning。
func (s *Scanner) hashEntry(displayPath, realPath string, info os.FileInfo, result *ScanResult, seen map[string]bool) error {
	if seen[displayPath] {
		return nil
	}
	if info.Size() > s.limits.MaxFileBytes {
		result.Warnings = append(result.Warnings, fmt.Sprintf("文件超过 %d 字节上限，跳过: %s", s.limits.MaxFileBytes, displayPath))
		return nil
	}
	if len(result.Entries) >= s.limits.MaxEntries {
		result.Truncated = true
		result.Warnings = append(result.Warnings, fmt.Sprintf("条目数达到上限 %d，扫描已截断（后续路径未处理）", s.limits.MaxEntries))
		return errStopScan
	}
	digest, err := hashFile(realPath)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			result.Warnings = append(result.Warnings, "文件不可读（权限不足），跳过: "+displayPath)
			return nil
		}
		result.Warnings = append(result.Warnings, "文件读取失败，跳过: "+displayPath)
		return nil
	}
	seen[displayPath] = true
	result.Entries = append(result.Entries, newEntry(displayPath, info, digest))
	result.TotalBytes += info.Size()
	return nil
}

// hashFile 流式计算文件 sha256；内容不进入返回值。
func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// newEntry 用文件元数据组装快照条目。
func newEntry(path string, info os.FileInfo, digest string) Entry {
	uid, gid := ownerIDs(info)
	return Entry{
		Path:   path,
		SHA256: digest,
		Size:   info.Size(),
		Mode:   fmt.Sprintf("%04o", info.Mode().Perm()),
		MTime:  info.ModTime().UTC().Format(time.RFC3339Nano),
		UID:    uid,
		GID:    gid,
	}
}

// compileExcludes 预校验 glob：非法模式回 E_INVALID，避免扫描中途才发现。
func compileExcludes(patterns []string) ([]string, *pluginapi.Error) {
	cleaned := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" {
			return nil, invalid("exclude 含空模式")
		}
		if hasControlRune(pattern) {
			return nil, invalid("exclude 含非法控制字符: " + pattern)
		}
		if _, err := filepath.Match(pattern, "x"); err != nil {
			return nil, invalid("exclude 模式非法: " + pattern)
		}
		cleaned = append(cleaned, pattern)
	}
	return cleaned, nil
}

// matchExclude 判定路径是否命中排除规则：
//   - 不含 "/" 的模式只匹配文件名（如 *.log）；
//   - 含 "/" 的模式匹配完整路径（如 /proc/* 同时把整棵子树排除）。
func matchExclude(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pattern := range patterns {
		if strings.Contains(pattern, "/") {
			if ok, _ := filepath.Match(pattern, path); ok {
				return true
			}
			if strings.HasSuffix(pattern, "/*") {
				prefix := strings.TrimSuffix(pattern, "*")
				if strings.HasPrefix(path, prefix) {
					return true
				}
			}
			continue
		}
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
	}
	return false
}

// HashFile 是 verify_file 使用的公共入口：解析路径并计算 sha256。
func (s *Scanner) HashFile(raw string) (string, int64, *pluginapi.Error) {
	real, perr := s.allow.ResolveExisting(raw)
	if perr != nil {
		return "", 0, perr
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", 0, invalid("路径不可访问: " + raw)
	}
	if info.IsDir() {
		return "", 0, invalid("verify_file 只接受文件，不接受目录: " + raw)
	}
	if info.Size() > s.limits.MaxFileBytes {
		return "", 0, invalid(fmt.Sprintf("文件超过 %d 字节上限: %s", s.limits.MaxFileBytes, raw))
	}
	digest, err := hashFile(real)
	if err != nil {
		return "", 0, invalid("文件不可读: " + raw)
	}
	return digest, info.Size(), nil
}
