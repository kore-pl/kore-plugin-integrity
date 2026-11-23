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

// MaxNoteLen 是基线说明的长度上限。
const MaxNoteLen = 200

// baselineParams 是 integrity.baseline 入参。
type baselineParams struct {
	Paths   []string `json:"paths"`
	Exclude []string `json:"exclude,omitempty"`
	// Note 是快照说明（≤200 字符，便于在历史列表里区分版本）。
	Note string `json:"note,omitempty"`
	// Keep 是保留的快照总数（含当前），1..100，缺省 DefaultBaselineKeep。
	Keep int `json:"keep,omitempty"`
}

// checkParams 是 integrity.check 入参：paths 可省略，省略时沿用基线记录的扫描根。
type checkParams struct {
	Paths   []string `json:"paths,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	// BaselineID 指定与哪个基线快照比对；空或 "latest" 表示当前最新。
	BaselineID string `json:"baseline_id,omitempty"`
}

// verifyFileParams 是 integrity.verify_file 入参。
type verifyFileParams struct {
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// baselineListParams 是 integrity.baseline.list 入参。
type baselineListParams struct {
	Limit int `json:"limit,omitempty"`
}

// BaselineResult 是 integrity.baseline 的结果。
type BaselineResult struct {
	Saved           bool     `json:"saved"`
	ID              string   `json:"id"`
	Note            string   `json:"note,omitempty"`
	Entries         int      `json:"entries"`
	TotalBytes      int64    `json:"total_bytes"`
	DurationMS      int64    `json:"duration_ms"`
	PreviousEntries int      `json:"previous_entries"`
	ArchivedID      string   `json:"archived_id,omitempty"`
	Kept            int      `json:"kept"`
	BaselineCount   int      `json:"baseline_count"`
	Warnings        []string `json:"warnings,omitempty"`
}

// BaselineListItem 是历史基线列表的一条（不含 entries）。
type BaselineListItem struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	Note        string `json:"note,omitempty"`
	Entries     int    `json:"entries"`
	TotalBytes  int64  `json:"total_bytes"`
	LastCheckAt string `json:"last_check_at,omitempty"`
	LastCheckOK *bool  `json:"last_check_ok,omitempty"`
	Current     bool   `json:"current"`
}

// restoreParams 是 integrity.restore 的入参。
type restoreParams struct {
	BaselineID string `json:"baseline_id"`
}

// RestoreResult 是 integrity.restore 的结果。
//
//	FromID 是覆盖前的当前基线（没有当前基线时为空），ToID 是恢复到的历史快照；
//	BackupPath 是覆盖前当前基线的同目录备份（0600），便于事后回看/再次回滚。
type RestoreResult struct {
	FromID     string `json:"from_id"`
	ToID       string `json:"to_id"`
	Entries    int    `json:"entries"`
	Restored   bool   `json:"restored"`
	BackupPath string `json:"backup_path,omitempty"`
	Hint       string `json:"hint"`
	// Verified 是恢复后自动复核的结论；Changes 是复核发现的差异条数。
	Verified bool `json:"verified"`
	Changes  int  `json:"changes"`
	// Alerts 是复核告警（结构同 check.alerts），供主壳告警中心消费。
	Alerts  []CheckAlert `json:"alerts,omitempty"`
	Message string       `json:"message,omitempty"`
}

// BaselineListResult 是 integrity.baseline.list 的结果。
type BaselineListResult struct {
	Baselines []BaselineListItem `json:"baselines"`
	Count     int                `json:"count"`
	Keep      int                `json:"keep"`
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

// CheckSummary 是本次比对的计数汇总（指标口径固定，便于告警与前端展示）。
type CheckSummary struct {
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Modified  int `json:"modified"`
	Unchanged int `json:"unchanged"`
	// Skipped 是扫描期被跳过 / 告警的条目数（结论可能不完整）。
	Skipped int `json:"skipped"`
}

// CheckResult 是 integrity.check 的结果。
type CheckResult struct {
	OK         bool            `json:"ok"`
	BaselineID string          `json:"baseline_id"`
	Added      []string        `json:"added"`
	Removed    []string        `json:"removed"`
	Modified   []ModifiedEntry `json:"modified"`
	// Changes 是带 severity 的结构化变更（added/removed/modified 摊平），供告警中心直接消费。
	Changes   []ChangeEntry `json:"changes"`
	Unchanged int           `json:"unchanged"`
	CheckedAt string        `json:"checked_at"`
	Truncated bool          `json:"truncated"`
	Summary   CheckSummary  `json:"summary"`
	Alerts    []CheckAlert  `json:"alerts"`
	Recovery  RecoveryGuide `json:"recovery"`
	Warnings  []string      `json:"warnings,omitempty"`
}

// StatusResult 是 integrity.status 的结果；从未建立的字段为 null 而不是零值。
type StatusResult struct {
	HasBaseline   bool    `json:"has_baseline"`
	CreatedAt     *string `json:"created_at"`
	Entries       int     `json:"entries"`
	TotalBytes    int64   `json:"total_bytes"`
	LastCheckAt   *string `json:"last_check_at"`
	LastCheckOK   *bool   `json:"last_check_ok"`
	BaselineCount int     `json:"baseline_count"`
	LatestID      *string `json:"latest_id"`
	LatestNote    *string `json:"latest_note,omitempty"`
}

// VerifyFileResult 是 integrity.verify_file 的结果。
type VerifyFileResult struct {
	Match          bool   `json:"match"`
	ActualSHA256   string `json:"actual_sha256"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

// Service 是业务方法共享的运行期依赖。
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

// Call 解析 params 并执行业务方法之一。
func (s *Service) Call(method string, params json.RawMessage) (any, *pluginapi.Error) {
	switch method {
	case "baseline":
		return s.baseline(params)
	case "baseline.list":
		return s.baselineList(params)
	case "restore":
		return s.restore(params)
	case "check":
		return s.check(params)
	case "status":
		return s.status(params)
	case "verify_file":
		return s.verifyFile(params)
	case "schedule.set":
		return s.scheduleSet(params)
	case "schedule.get":
		return s.scheduleGet(params)
	default:
		return nil, &pluginapi.Error{Code: pluginapi.E_NOTFOUND, Message: "未知方法：" + method}
	}
}

// restore 把指定历史快照恢复为当前基线：覆盖前先备份并归档当前基线，幂等。
func (s *Service) restore(raw json.RawMessage) (any, *pluginapi.Error) {
	var p restoreParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	id := strings.TrimSpace(p.BaselineID)
	if id == "" {
		return nil, invalid("缺少必填字段 baseline_id")
	}
	if err := validateSnapshotID(id); err != nil {
		return nil, invalid("baseline_id 非法: " + err.Error())
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	target, err := s.store.LoadSnapshot(id)
	if err != nil {
		if errors.Is(err, ErrNoSnapshot) {
			return nil, notFoundErr("未找到基线快照 "+id, s.snapshotHint())
		}
		return nil, internalErr(err.Error())
	}
	current, err := s.store.Load()
	if err != nil && !errors.Is(err, ErrNoBaseline) {
		return nil, internalErr(err.Error())
	}
	result := RestoreResult{ToID: target.ID, Entries: len(target.Entries)}
	if err == nil {
		result.FromID = current.ID
		// 幂等：已经是目标版本时不备份、不写盘。
		if current.ID == target.ID {
			result.Restored = false
			result.Hint = "当前基线已是该快照，无需恢复"
			return result, nil
		}
		backupPath, backupErr := s.store.BackupCurrent(s.now())
		if backupErr != nil {
			return nil, internalErr("备份当前基线失败: " + backupErr.Error())
		}
		result.BackupPath = backupPath
		// 把被替换的当前基线也归档进历史：恢复后仍可再回滚到它。
		if _, archiveErr := s.store.Archive(current); archiveErr != nil {
			return nil, internalErr("归档当前基线失败: " + archiveErr.Error())
		}
	}
	if err := s.store.Save(target); err != nil {
		return nil, internalErr("恢复基线失败: " + err.Error())
	}
	result.Restored = true
	result.Hint = "已恢复为历史快照；原当前基线已备份到 backup_path 并归档进历史"
	// 恢复后自动复核：恢复的是"基线记录"而不是文件内容；当前文件若与目标基线不一致，
	// 必须如实告诉用户"恢复成功但仍有差异"，不能让人误以为恢复=干净。
	if checked, perr := s.check(json.RawMessage(`{}`)); perr != nil {
		result.Verified = false
		result.Message = "恢复成功但复核失败：" + perr.Message
	} else if recheck, ok := checked.(CheckResult); ok {
		result.Verified = recheck.OK
		result.Changes = len(recheck.Changes)
		result.Alerts = recheck.Alerts
		if recheck.OK {
			result.Message = "恢复成功且复核无差异"
		} else {
			result.Message = fmt.Sprintf("恢复成功但复核发现仍有 %d 处不一致", len(recheck.Changes))
		}
	}
	return result, nil
}

// snapshotHint 汇总可用快照 id（最多 10 个），用于 E_NOTFOUND 的可操作提示。
func (s *Service) snapshotHint() string {
	metas, err := s.store.ListSnapshots()
	if err != nil || len(metas) == 0 {
		return "用 integrity.baseline.list 查看可用快照"
	}
	ids := make([]string, 0, 10)
	for _, meta := range metas {
		if len(ids) >= 10 {
			break
		}
		ids = append(ids, meta.ID)
	}
	hint := "可用快照: " + strings.Join(ids, ", ")
	if len(metas) > len(ids) {
		hint += " …"
	}
	return hint
}

// baseline 建立新的基线快照：旧当前基线进入历史，再按 keep 裁剪历史。
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
	note, perr := normalizeNote(p.Note)
	if perr != nil {
		return nil, perr
	}
	keep := p.Keep
	if keep == 0 {
		keep = DefaultBaselineKeep
	}
	if keep < 1 || keep > MaxBaselineKeep {
		return nil, invalid(fmt.Sprintf("keep 必须在 1–%d 之间", MaxBaselineKeep))
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	previous, err := s.store.Load()
	if err != nil && !errors.Is(err, ErrNoBaseline) {
		return nil, internalErr(err.Error())
	}
	if errors.Is(err, ErrNoBaseline) {
		previous = nil
	}
	started := s.now()
	scan, perr := s.scanner.Scan(p.Paths, p.Exclude)
	if perr != nil {
		return nil, perr
	}
	now := s.now().UTC()
	baseline := &Baseline{
		ID:         newBaselineID(s.store, now),
		Note:       note,
		Version:    baselineVersion,
		CreatedAt:  now.Format(time.RFC3339Nano),
		Roots:      append([]string(nil), p.Paths...),
		Exclude:    append([]string(nil), p.Exclude...),
		Entries:    scan.Entries,
		TotalBytes: scan.TotalBytes,
	}
	result := BaselineResult{
		Saved:      true,
		ID:         baseline.ID,
		Note:       note,
		Entries:    len(scan.Entries),
		TotalBytes: scan.TotalBytes,
		DurationMS: s.now().Sub(started).Milliseconds(),
		Kept:       keep,
		Warnings:   append([]string(nil), scan.Warnings...),
	}
	// 先把旧快照写进历史（含索引），再替换当前基线：任一步失败都不会丢上一份基线。
	if previous != nil {
		result.PreviousEntries = len(previous.Entries)
		meta, archiveErr := s.store.Archive(previous)
		if archiveErr != nil {
			return nil, internalErr("归档上一份基线失败: " + archiveErr.Error())
		}
		result.ArchivedID = meta.ID
	}
	if err := s.store.Save(baseline); err != nil {
		return nil, internalErr("保存基线失败: " + err.Error())
	}
	if _, pruneErr := s.store.Prune(keep); pruneErr != nil {
		result.Warnings = append(result.Warnings, "裁剪历史基线失败: "+pruneErr.Error())
	}
	// keep=1 时上一份基线刚归档就被裁掉，不要把已被删除的 id 回给调用方。
	if result.ArchivedID != "" && !s.store.SnapshotExists(result.ArchivedID) {
		result.ArchivedID = ""
	}
	if metas, listErr := s.store.ListSnapshots(); listErr == nil {
		result.BaselineCount = len(metas)
	}
	return result, nil
}

// baselineList 列出当前与历史基线快照（不含 entries）。
func (s *Service) baselineList(raw json.RawMessage) (any, *pluginapi.Error) {
	var p baselineListParams
	if perr := decodeParams(raw, &p); perr != nil {
		return nil, perr
	}
	limit := p.Limit
	if limit == 0 {
		limit = MaxBaselineKeep
	}
	if limit < 1 || limit > MaxBaselineKeep {
		return nil, invalid(fmt.Sprintf("limit 必须在 1–%d 之间", MaxBaselineKeep))
	}
	if perr := s.requireState(); perr != nil {
		return nil, perr
	}
	metas, err := s.store.ListSnapshots()
	if err != nil {
		return nil, internalErr(err.Error())
	}
	result := BaselineListResult{Baselines: []BaselineListItem{}, Keep: DefaultBaselineKeep}
	for _, meta := range metas {
		if len(result.Baselines) >= limit {
			break
		}
		result.Baselines = append(result.Baselines, BaselineListItem{
			ID:          meta.ID,
			CreatedAt:   meta.CreatedAt,
			Note:        meta.Note,
			Entries:     meta.Entries,
			TotalBytes:  meta.TotalBytes,
			LastCheckAt: meta.LastCheckAt,
			LastCheckOK: meta.LastCheckOK,
			Current:     meta.Current,
		})
	}
	result.Count = len(result.Baselines)
	return result, nil
}

// check 对比当前状态与指定基线（缺省最新），产出三态、汇总、告警与恢复指引。
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
	baselineID := strings.TrimSpace(p.BaselineID)
	if baselineID == "latest" {
		baselineID = ""
	}
	var baseline *Baseline
	var err error
	isCurrent := baselineID == ""
	if isCurrent {
		baseline, err = s.store.Load()
	} else {
		baseline, err = s.store.LoadSnapshot(baselineID)
		if err == nil {
			// 显式 id 命中的也可能就是当前基线；只有历史快照才走 SaveArchived。
			if current, loadErr := s.store.Load(); loadErr == nil && current.ID == baseline.ID {
				isCurrent = true
			}
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, ErrNoBaseline):
			return nil, notFoundErr("尚未建立完整性基线", "先调用 integrity.baseline 建立基线")
		case errors.Is(err, ErrNoSnapshot):
			return nil, notFoundErr("未找到基线快照 "+baselineID, "用 integrity.baseline.list 查看可用快照")
		default:
			return nil, internalErr(err.Error())
		}
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
	result.BaselineID = baseline.ID
	result.Truncated = scan.Truncated
	result.Warnings = scan.Warnings
	result.Summary = buildSummary(result, len(scan.Warnings))
	result.Alerts = buildAlerts(result, scan.Truncated)
	result.Changes = buildChanges(result)
	result.Recovery = recoveryGuide(result)
	result.OK = len(result.Added) == 0 && len(result.Removed) == 0 && len(result.Modified) == 0

	// 记录最近一次检查结论；写失败不掩盖本次检查结果，只降级为 warning。
	baseline.LastCheckAt = result.CheckedAt
	baseline.LastCheckOK = &result.OK
	var saveErr error
	if isCurrent {
		saveErr = s.store.Save(baseline)
	} else {
		saveErr = s.store.SaveArchived(baseline)
	}
	if saveErr != nil {
		result.Warnings = append(result.Warnings, "更新基线检查状态失败: "+saveErr.Error())
	}
	return result, nil
}

// status 返回当前基线元信息与历史数量，不扫描文件系统。
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
	id := baseline.ID
	result := StatusResult{
		HasBaseline:   true,
		CreatedAt:     &createdAt,
		Entries:       len(baseline.Entries),
		TotalBytes:    baseline.TotalBytes,
		BaselineCount: 1,
		LatestID:      &id,
	}
	if baseline.Note != "" {
		note := baseline.Note
		result.LatestNote = &note
	}
	if baseline.LastCheckAt != "" {
		last := baseline.LastCheckAt
		result.LastCheckAt = &last
	}
	result.LastCheckOK = baseline.LastCheckOK
	if metas, listErr := s.store.ListSnapshots(); listErr == nil {
		result.BaselineCount = len(metas)
	}
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

// normalizeNote 校验并归一化基线说明：≤200 字符，不含控制字符。
func normalizeNote(raw string) (string, *pluginapi.Error) {
	note := strings.TrimSpace(raw)
	if len(note) > MaxNoteLen {
		return "", invalid(fmt.Sprintf("note 超过 %d 字符上限", MaxNoteLen))
	}
	if hasControlRune(note) {
		return "", invalid("note 含非法控制字符")
	}
	return note, nil
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
		Alerts:    []CheckAlert{},
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
