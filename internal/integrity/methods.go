package integrity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// MaxPaths 是单次 baseline/check 的路径条数上限。
const MaxPaths = 256

// baselineParams 是 integrity.baseline 入参。
type baselineParams struct {
	Paths   []string `json:"paths"`
	Exclude []string `json:"exclude,omitempty"`
}

// checkParams 是 integrity.check 入参：paths 可省略，省略时沿用基线记录的扫描根。
type checkParams struct {
	Paths   []string `json:"paths,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// verifyFileParams 是 integrity.verify_file 入参。
type verifyFileParams struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// BaselineResult 是 integrity.baseline 的结果。
type BaselineResult struct {
	Saved           bool     `json:"saved"`
	Entries         int      `json:"entries"`
	TotalBytes      int64    `json:"total_bytes"`
	DurationMS      int64    `json:"duration_ms"`
	PreviousEntries int      `json:"previous_entries"`
	Warnings        []string `json:"warnings,omitempty"`
}

// ModifiedEntry 是单条被修改文件的结构化差异（只比 sha256 与 mode）。
type ModifiedEntry struct {
	Path      string   `json:"path"`
	OldSHA256 string   `json:"old_sha256"`
	NewSHA256 string   `json:"new_sha256"`
	OldMode   string   `json:"old_mode"`
	NewMode   string   `json:"new_mode"`
	Changes   []string `json:"changes"`
}

// CheckResult 是 integrity.check 的结果。
type CheckResult struct {
	OK        bool            `json:"ok"`
	Added     []string        `json:"added"`
	Removed   []string        `json:"removed"`
	Modified  []ModifiedEntry `json:"modified"`
	Unchanged int             `json:"unchanged"`
	CheckedAt string          `json:"checked_at"`
	Warnings  []string        `json:"warnings,omitempty"`
}

// StatusResult 是 integrity.status 的结果；从未建立的字段为 null 而不是零值。
type StatusResult struct {
	HasBaseline bool    `json:"has_baseline"`
	CreatedAt   *string `json:"created_at"`
	Entries     int     `json:"entries"`
	TotalBytes  int64   `json:"total_bytes"`
	LastCheckAt *string `json:"last_check_at"`
	LastCheckOK *bool   `json:"last_check_ok"`
}

// VerifyFileResult 是 integrity.verify_file 的结果。
type VerifyFileResult struct {
	Match          bool   `json:"match"`
	ActualSHA256   string `json:"actual_sha256"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// Service 是四个业务方法共享的运行期依赖。
type Service struct {
	store   *Store
	allow   *Allowlist
	scanner *Scanner
	now     func() time.Time
}

// NewService 构造服务：stateDir 为插件状态目录（KORE_STATE_DIR），
// extraRoots 为 KORE_INTEGRITY_ALLOW_ROOTS 解析出的额外白名单根。
func NewService(stateDir string, extraRoots []string, limits Limits) *Service {
	allow := NewAllowlist(stateDir, extraRoots)
	return &Service{
		store:   NewStore(stateDir),
		allow:   allow,
		scanner: NewScanner(allow, limits),
		now:     time.Now,
	}
}

// SetNow 注入时钟，仅供测试使用。
func (s *Service) SetNow(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// Call 解析 params 并执行四个业务方法之一。
func (s *Service) Call(method string, params json.RawMessage) (any, *pluginapi.Error) {
	switch method {
	case "baseline":
		return s.baseline(params)
	case "check":
		return s.check(params)
	case "status":
		return s.status(params)
	case "verify_file":
		return s.verifyFile(params)
	default:
		return nil, &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
	}
}

// baseline 建立（覆盖）基线快照。
func (s *Service) baseline(raw json.RawMessage) (any, *pluginapi.Error) {
	var p baselineParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if len(p.Paths) == 0 {
		return nil, invalid("缺少必填字段 paths")
	}
	if perr := validatePathCount(p.Paths); perr != nil {
		return nil, perr
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	started := s.now()
	previous := 0
	if prior, err := s.store.Load(); err == nil {
		previous = len(prior.Entries)
	} else if !errors.Is(err, ErrNoBaseline) {
		return nil, internalErr(err.Error())
	}
	scan, perr := s.scanner.Scan(p.Paths, p.Exclude)
	if perr != nil {
		return nil, perr
	}
	createdAt := started.UTC().Format(time.RFC3339Nano)
	baseline := &Baseline{
		Version:    baselineVersion,
		CreatedAt:  createdAt,
		Roots:      append([]string(nil), p.Paths...),
		Exclude:    append([]string(nil), p.Exclude...),
		Entries:    scan.Entries,
		TotalBytes: scan.TotalBytes,
	}
	if err := s.store.Save(baseline); err != nil {
		return nil, internalErr("保存基线失败: " + err.Error())
	}
	return BaselineResult{
		Saved:           true,
		Entries:         len(scan.Entries),
		TotalBytes:      scan.TotalBytes,
		DurationMS:      s.now().Sub(started).Milliseconds(),
		PreviousEntries: previous,
		Warnings:        scan.Warnings,
	}, nil
}

// check 对比当前状态与基线，产出 added / removed / modified / unchanged。
func (s *Service) check(raw json.RawMessage) (any, *pluginapi.Error) {
	var p checkParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := validatePathCount(p.Paths); perr != nil {
		return nil, perr
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	baseline, err := s.store.Load()
	if err != nil {
		if errors.Is(err, ErrNoBaseline) {
			return nil, notFoundErr("尚未建立完整性基线", "先调用 integrity.baseline 建立基线")
		}
		return nil, internalErr(err.Error())
	}
	paths := p.Paths
	if len(paths) == 0 {
		paths = baseline.Roots
	}
	if len(paths) == 0 {
		return nil, internalErr("基线未记录扫描根，请显式传入 paths")
	}
	exclude := p.Exclude
	if len(exclude) == 0 {
		exclude = baseline.Exclude
	}
	scan, perr := s.scanner.Scan(paths, exclude)
	if perr != nil {
		return nil, perr
	}
	result := compareEntries(baseline.Entries, scan.Entries, s.now().UTC())
	result.Warnings = scan.Warnings
	ok := len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Modified) == 0
	result.OK = ok

	// 记录最近一次检查结论；写失败不掩盖本次检查结果，只降级为 warning。
	baseline.LastCheckAt = result.CheckedAt
	baseline.LastCheckOK = &ok
	if saveErr := s.store.Save(baseline); saveErr != nil {
		result.Warnings = append(result.Warnings, "更新基线检查状态失败: "+saveErr.Error())
	}
	return result, nil
}

// status 返回基线元信息，不扫描文件系统。
func (s *Service) status(raw json.RawMessage) (any, *pluginapi.Error) {
	if perr := decodeParams(raw, &struct{}{}); perr != nil {
		return nil, perr
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	baseline, err := s.store.Load()
	if err != nil {
		if errors.Is(err, ErrNoBaseline) {
			return StatusResult{HasBaseline: false}, nil
		}
		return nil, internalErr(err.Error())
	}
	createdAt := baseline.CreatedAt
	result := StatusResult{
		HasBaseline: true,
		CreatedAt:   &createdAt,
		Entries:     len(baseline.Entries),
		TotalBytes:  baseline.TotalBytes,
	}
	if baseline.LastCheckAt != "" {
		last := baseline.LastCheckAt
		result.LastCheckAt = &last
	}
	result.LastCheckOK = baseline.LastCheckOK
	return result, nil
}

// verifyFile 校验单文件 sha256。
func (s *Service) verifyFile(raw json.RawMessage) (any, *pluginapi.Error) {
	var p verifyFileParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	if p.Path == "" {
		return nil, invalid("缺少必填字段 path")
	}
	expected, perr := normalizeSHA256(p.ExpectedSHA256)
	if perr != nil {
		return nil, perr
	}
	actual, _, perr := s.scanner.HashFile(p.Path)
	if perr != nil {
		return nil, perr
	}
	return VerifyFileResult{Match: actual == expected, ActualSHA256: actual, ExpectedSHA256: expected}, nil
}

// requireState 保证状态目录可用：没有它就无法落基线，早失败并给 hint。
func (s *Service) requireState() *pluginapi.Error {
	if s.store.Dir() == "" {
		return &pluginapi.Error{
			Code:    pluginapi.E_INTERNAL,
			Message: "KORE_STATE_DIR 未设置，无法定位基线文件",
			Detail:  hintDetail("由内核注入 KORE_STATE_DIR 后重试（本地调试可手动设置）"),
		}
	}
	return nil
}

// decodeParams 把载荷按 JSON 对象解码；空载荷等价空对象。
func decodeParams(raw json.RawMessage, dst any) *pluginapi.Error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if raw[0] != '{' {
		return invalid("params 必须是 JSON 对象")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return invalid("params 解析失败: " + err.Error())
	}
	return nil
}

// validatePathCount 限制路径条数，防超大请求。
func validatePathCount(paths []string) *pluginapi.Error {
	if len(paths) > MaxPaths {
		return invalid(fmt.Sprintf("paths 超过 %d 条上限", MaxPaths))
	}
	return nil
}

// normalizeSHA256 校验并归一化期望摘要：64 位十六进制，统一小写。
func normalizeSHA256(raw string) (string, *pluginapi.Error) {
	expected := strings.ToLower(strings.TrimSpace(raw))
	if expected == "" {
		return "", invalid("缺少必填字段 expected_sha256")
	}
	if len(expected) != 64 {
		return "", invalid("expected_sha256 必须是 64 位十六进制")
	}
	if _, err := hex.DecodeString(expected); err != nil {
		return "", invalid("expected_sha256 必须是 64 位十六进制")
	}
	return expected, nil
}

// compareEntries 计算基线集合与当前集合的差异。
func compareEntries(before, current []Entry, now time.Time) CheckResult {
	previous := make(map[string]Entry, len(before))
	for _, entry := range before {
		previous[entry.Path] = entry
	}
	present := make(map[string]Entry, len(current))
	for _, entry := range current {
		present[entry.Path] = entry
	}
	result := CheckResult{
		Added:     make([]string, 0),
		Removed:   make([]string, 0),
		Modified:  make([]ModifiedEntry, 0),
		CheckedAt: now.Format(time.RFC3339Nano),
	}
	for path, entry := range present {
		old, existed := previous[path]
		if !existed {
			result.Added = append(result.Added, path)
			continue
		}
		changed := make([]string, 0, 2)
		if old.SHA256 != entry.SHA256 {
			changed = append(changed, "sha256")
		}
		if old.Mode != entry.Mode {
			changed = append(changed, "mode")
		}
		if len(changed) > 0 {
			result.Modified = append(result.Modified, ModifiedEntry{
				Path:      path,
				OldSHA256: old.SHA256,
				NewSHA256: entry.SHA256,
				OldMode:   old.Mode,
				NewMode:   entry.Mode,
				Changes:   changed,
			})
			continue
		}
		result.Unchanged++
	}
	for path := range previous {
		if _, exists := present[path]; !exists {
			result.Removed = append(result.Removed, path)
		}
	}
	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Slice(result.Modified, func(i, j int) bool { return result.Modified[i].Path < result.Modified[j].Path })
	return result
}
