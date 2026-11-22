package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// allowedRoots 是路径白名单：只接受这些宿主配置根目录下的文件。
// 骨架口径不实际访问文件系统，白名单仅对入参做静态校验，防止越权路径进入后续实现。
var allowedRoots = []string{"/etc", "/usr/local/etc", "/opt/kore", "/var/www"}

// maxPaths 是单次基线/校验的路径条数上限，防止超大请求（帧上限 8 MiB 之外的二次约束）。
const maxPaths = 256

// baselineParams 是 integrity.baseline 入参：待登记哈希的文件路径列表。
type baselineParams struct {
	Paths []string `json:"paths"`
}

// verifyParams 是 integrity.verify 入参：待比对路径列表与可选基线 id。
type verifyParams struct {
	Paths      []string `json:"paths"`
	BaselineID string   `json:"baseline_id,omitempty"`
}

// fileDigest 是单条结构化摘要记录。
type fileDigest struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// baselineResult 是 integrity.baseline 的结构化结果。
type baselineResult struct {
	BaselineID string       `json:"baseline_id"`
	Scanned    bool         `json:"scanned"`
	Count      int          `json:"count"`
	Entries    []fileDigest `json:"entries"`
}

// changeRecord 是 verify 检出的单条变更。
type changeRecord struct {
	Path   string `json:"path"`
	Status string `json:"status"`
}

// verifyResult 是 integrity.verify 的结构化结果。
type verifyResult struct {
	BaselineID string         `json:"baseline_id"`
	Scanned    bool           `json:"scanned"`
	Changed    int            `json:"changed"`
	Alert      bool           `json:"alert"`
	Changes    []changeRecord `json:"changes"`
}

// parseBaselineParams 校验 baseline 入参：对象形状、路径非空与白名单。
func parseBaselineParams(raw json.RawMessage) (baselineParams, *pluginapi.Error) {
	var p baselineParams
	if perr := decodeParams(raw, &p); perr != nil {
		return p, perr
	}
	if perr := validatePaths(p.Paths); perr != nil {
		return p, perr
	}
	return p, nil
}

// parseVerifyParams 校验 verify 入参：对象形状、路径非空与白名单。
func parseVerifyParams(raw json.RawMessage) (verifyParams, *pluginapi.Error) {
	var p verifyParams
	if perr := decodeParams(raw, &p); perr != nil {
		return p, perr
	}
	if perr := validatePaths(p.Paths); perr != nil {
		return p, perr
	}
	return p, nil
}

// decodeParams 把 raw 按 JSON 对象解码到目标结构，空载荷按空对象处理。
func decodeParams(raw json.RawMessage, dst any) *pluginapi.Error {
	if len(raw) != 0 && string(raw) != "null" {
		if raw[0] != '{' {
			return invalidParam("params 必须是 JSON 对象")
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return invalidParam("params 解析失败: " + err.Error())
		}
	}
	return nil
}

// validatePaths 校验路径列表：至少一条、不超过上限、每条都在白名单内。
func validatePaths(paths []string) *pluginapi.Error {
	if len(paths) == 0 {
		return invalidParam("缺少必填字段 paths")
	}
	if len(paths) > maxPaths {
		return invalidParam("paths 超过 256 条上限")
	}
	for _, p := range paths {
		if perr := validatePath(p); perr != nil {
			return perr
		}
	}
	return nil
}

// validatePath 校验单条路径：必须绝对、规范、在白名单根下，拒绝 ".." 与空字节。
func validatePath(path string) *pluginapi.Error {
	if path == "" {
		return invalidParam("paths 含空路径")
	}
	if !filepath.IsAbs(path) {
		return invalidParam("路径必须是绝对路径: " + path)
	}
	if strings.ContainsRune(path, 0) || strings.Contains(path, "\n") {
		return invalidParam("路径含非法控制字符: " + path)
	}
	clean := filepath.Clean(path)
	if clean != path || strings.Contains(clean, "..") {
		return invalidParam("路径必须规范且不含 ..: " + path)
	}
	for _, root := range allowedRoots {
		if clean == root || strings.HasPrefix(clean, root+string(filepath.Separator)) {
			return nil
		}
	}
	return invalidParam("路径不在白名单内: " + path)
}

// runBaseline 生成基线：对每条白名单路径计算占位摘要，scanned=false 表明未读宿主 FS。
func runBaseline(p baselineParams) baselineResult {
	entries := make([]fileDigest, 0, len(p.Paths))
	for _, path := range p.Paths {
		entries = append(entries, fileDigest{
			Path: path, SHA256: placeholderDigest(path), SizeBytes: 0,
		})
	}
	return baselineResult{BaselineID: digestID(p.Paths), Scanned: false, Count: len(entries), Entries: entries}
}

// runVerify 生成比对结果：骨架口径下不读文件，所有路径记为 unchanged，alert=false。
func runVerify(p verifyParams) verifyResult {
	changes := make([]changeRecord, 0, len(p.Paths))
	for _, path := range p.Paths {
		changes = append(changes, changeRecord{Path: path, Status: "unchanged"})
	}
	id := p.BaselineID
	if id == "" {
		id = digestID(p.Paths)
	}
	return verifyResult{BaselineID: id, Scanned: false, Changed: 0, Alert: false, Changes: changes}
}

// placeholderDigest 用 sha256 标准库对路径字符串取摘要，作为骨架占位值。
// 它不读取文件内容——真扫描留待生产级迭代，这样保证结果确定且零宿主副作用。
func placeholderDigest(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:])
}

// digestID 由路径集合的稳定摘要生成基线 id，保证同样输入得到同样 id。
func digestID(paths []string) string {
	sum := sha256.New()
	for _, p := range paths {
		_, _ = sum.Write([]byte(p))
		_, _ = sum.Write([]byte{0x00})
	}
	return hex.EncodeToString(sum.Sum(nil)[:16])
}
