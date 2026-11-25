package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// 多版本基线布局（0.3.0 起）：
//
//	<state>/baseline.json        当前（最新）基线快照；0.2.0 的旧文件直接兼容
//	<state>/baselines/<id>.json  历史快照
//	<state>/baselines/index.json 历史快照元信息（不含 entries，避免一次加载全部历史）
//
// 语义保持不变：baseline 是快照；check 默认与最新基线比对，
// 也可用 baseline_id 指定历史快照。
const (
	// baselineFileName 是当前（最新）基线文件名，固定在插件状态目录下。
	baselineFileName = "baseline.json"
	// baselineDirName 是历史快照目录名。
	baselineDirName = "baselines"
	// indexFileName 是历史快照索引文件名。
	indexFileName = "index.json"
	// baselineVersion 是当前基线文件 schema 版本；1 为 0.2.0 的旧格式（兼容读取）。
	baselineVersion       = 2
	legacyBaselineVersion = 1
	// indexVersion 是历史索引 schema 版本。
	indexVersion = 1
	// DefaultBaselineKeep 是默认保留的基线快照数（含当前），1..100。
	DefaultBaselineKeep = 10
	// MaxBaselineKeep 是保留数的上限。
	MaxBaselineKeep = 100
)

// ErrNoBaseline 表示状态目录中还没有当前基线。
var ErrNoBaseline = errors.New("尚未建立完整性基线")

// ErrNoSnapshot 表示按 id 找不到历史基线快照。
var ErrNoSnapshot = errors.New("未找到指定的基线快照")

// Baseline 是落盘的基线快照。基线是快照语义：再次 baseline 会生成新快照，
// 旧快照进入历史（受保留策略约束），不再原地覆盖。
type Baseline struct {
	// ID 是快照 id（baseline-<UTC 时间戳>）；0.2.0 旧文件没有该字段，读取时按 CreatedAt 派生。
	ID string `json:"id,omitempty"`
	// Note 是建立基线时填写的说明（≤200 字符）。
	Note string `json:"note,omitempty"`
	// Version 是 schema 版本：1（0.2.0 旧格式）/ 2（当前）。
	Version    int      `json:"version"`
	CreatedAt  string   `json:"created_at"`
	Roots      []string `json:"roots"`
	Exclude    []string `json:"exclude,omitempty"`
	Entries    []Entry  `json:"entries"`
	TotalBytes int64    `json:"total_bytes"`
	// LastCheckAt 是最近一次 check 的时刻；从未 check 时为空。
	LastCheckAt string `json:"last_check_at,omitempty"`
	// LastCheckOK 是最近一次 check 的结论；从未 check 时为 null。
	LastCheckOK *bool `json:"last_check_ok,omitempty"`
}

// SnapshotMeta 是一条基线快照的元信息（不含 entries）。
type SnapshotMeta struct {
	ID          string `json:"id"`
	CreatedAt   string `json:"created_at"`
	Note        string `json:"note,omitempty"`
	Entries     int    `json:"entries"`
	TotalBytes  int64  `json:"total_bytes"`
	LastCheckAt string `json:"last_check_at,omitempty"`
	LastCheckOK *bool  `json:"last_check_ok,omitempty"`
	// Roots 是该快照建立时记录的扫描根，随索引落盘（0.6.0 起），供 baseline.list
	// 直接回报"这个版本扫的是哪些路径"，无需为列表再解析完整的快照文件。
	// 上界：keep ≤ MaxBaselineKeep(100) × paths ≤ MaxPaths(256)，全打满约 1 MB；
	// 默认 keep=10 时约 100 KiB 量级，远小于单插件内存红线（G-03）。
	Roots []string `json:"roots,omitempty"`
	// Current 是计算字段：该快照是否为当前基线；不写入索引。
	Current bool `json:"current,omitempty"`
}

// indexFile 是历史快照索引的落盘形状。
type indexFile struct {
	Version   int            `json:"version"`
	Snapshots []SnapshotMeta `json:"snapshots"`
}

// Store 管理状态目录下的当前基线与历史快照。
type Store struct {
	dir string
}

// NewStore 构造状态存储；dir 为空时所有读写返回错误（由调用方转 E_INTERNAL）。
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

// Dir 返回状态目录。
func (s *Store) Dir() string {
	return s.dir
}

// Path 返回当前基线文件绝对路径（兼容 0.2.0 的口径）。
func (s *Store) Path() string {
	if s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, baselineFileName)
}

// ArchivesDir 返回历史快照目录。
func (s *Store) ArchivesDir() string {
	if s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, baselineDirName)
}

// Load 读取当前基线：文件不存在返回 ErrNoBaseline，内容损坏/版本不支持返回错误。
func (s *Store) Load() (*Baseline, error) {
	if s.dir == "" {
		return nil, errors.New("KORE_STATE_DIR 未设置")
	}
	baseline, err := readBaselineFile(s.Path())
	if err != nil {
		return nil, err
	}
	baseline.ID = deriveBaselineID(baseline)
	return baseline, nil
}

// Save 原子写入当前基线：临时文件 + fsync + rename，权限 0600。
func (s *Store) Save(baseline *Baseline) error {
	if s.dir == "" {
		return errors.New("KORE_STATE_DIR 未设置")
	}
	if baseline.ID == "" {
		baseline.ID = deriveBaselineID(baseline)
	}
	if baseline.Version == 0 {
		baseline.Version = baselineVersion
	}
	return writeJSONAtomic(s.Path(), baseline)
}

// BackupCurrent 把当前基线复制到 <state>/baseline.bak.<UTC 纳秒>.json（0600 原子写），
// 供 integrity.restore 覆盖当前基线前留证；文件名冲突时追加序号。
func (s *Store) BackupCurrent(now time.Time) (string, error) {
	if s.dir == "" {
		return "", errors.New("KORE_STATE_DIR 未设置")
	}
	current, err := s.Load()
	if err != nil {
		return "", err
	}
	base := filepath.Join(s.dir, "baseline.bak."+now.UTC().Format("20060102T150405.000000000Z"))
	target := base + ".json"
	for suffix := 2; ; suffix++ {
		if _, statErr := os.Stat(target); errors.Is(statErr, os.ErrNotExist) {
			break
		}
		target = fmt.Sprintf("%s-%d.json", base, suffix)
	}
	if err := writeJSONAtomic(target, current); err != nil {
		return "", err
	}
	return target, nil
}

// LoadSnapshot 按 id 读取快照：id 命中当前基线或历史文件都可以。
func (s *Store) LoadSnapshot(id string) (*Baseline, error) {
	if s.dir == "" {
		return nil, errors.New("KORE_STATE_DIR 未设置")
	}
	if err := validateSnapshotID(id); err != nil {
		return nil, err
	}
	if current, err := s.Load(); err == nil {
		if current.ID == id {
			return current, nil
		}
	} else if !errors.Is(err, ErrNoBaseline) {
		return nil, err
	}
	baseline, err := readBaselineFile(s.snapshotPath(id))
	if err != nil {
		if errors.Is(err, ErrNoBaseline) {
			return nil, ErrNoSnapshot
		}
		return nil, err
	}
	baseline.ID = id
	return baseline, nil
}

// Archive 把一份即将被替换的基线写入历史快照并更新索引；重复归档同一 id 是幂等的。
func (s *Store) Archive(baseline *Baseline) (SnapshotMeta, error) {
	if s.dir == "" {
		return SnapshotMeta{}, errors.New("KORE_STATE_DIR 未设置")
	}
	if baseline.ID == "" {
		baseline.ID = deriveBaselineID(baseline)
	}
	if err := validateSnapshotID(baseline.ID); err != nil {
		return SnapshotMeta{}, err
	}
	if err := s.writeArchive(baseline); err != nil {
		return SnapshotMeta{}, err
	}
	meta := metaFromBaseline(baseline)
	if err := s.upsertIndexMeta(meta); err != nil {
		return SnapshotMeta{}, err
	}
	return meta, nil
}

// SaveArchived 回写历史快照（例如 check 更新 last_check 字段）并同步索引元信息。
// 与 Archive 不同，这里总是重写文件，保证 last_check 字段真的落盘。
func (s *Store) SaveArchived(baseline *Baseline) error {
	if baseline.ID == "" {
		return errors.New("历史快照缺少 id")
	}
	if err := validateSnapshotID(baseline.ID); err != nil {
		return err
	}
	if err := s.writeArchive(baseline); err != nil {
		return err
	}
	return s.upsertIndexMeta(metaFromBaseline(baseline))
}

// writeArchive 原子写一份历史快照文件（版本旧则升级为当前版本）。
func (s *Store) writeArchive(baseline *Baseline) error {
	if err := os.MkdirAll(s.ArchivesDir(), 0o700); err != nil {
		return fmt.Errorf("创建历史快照目录: %w", err)
	}
	if baseline.Version < baselineVersion {
		baseline.Version = baselineVersion
	}
	if err := writeJSONAtomic(s.snapshotPath(baseline.ID), baseline); err != nil {
		return fmt.Errorf("写入历史快照: %w", err)
	}
	return nil
}

// upsertIndexMeta 把一条元信息写入索引（不存在则追加）。
func (s *Store) upsertIndexMeta(meta SnapshotMeta) error {
	index, err := s.readIndex()
	if err != nil {
		return err
	}
	index.Snapshots = upsertMeta(index.Snapshots, meta)
	return s.writeIndex(index)
}

// ListSnapshots 返回当前基线 + 历史快照的元信息，按创建时间倒序（当前标记 Current）。
func (s *Store) ListSnapshots() ([]SnapshotMeta, error) {
	if s.dir == "" {
		return nil, errors.New("KORE_STATE_DIR 未设置")
	}
	var metas []SnapshotMeta
	if current, err := s.Load(); err == nil {
		meta := metaFromBaseline(current)
		meta.Current = true
		metas = append(metas, meta)
	} else if !errors.Is(err, ErrNoBaseline) {
		return nil, err
	}
	index, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(metas))
	for _, meta := range metas {
		seen[meta.ID] = true
	}
	for _, meta := range index.Snapshots {
		if seen[meta.ID] {
			continue
		}
		metas = append(metas, meta)
	}
	sort.Slice(metas, func(i, j int) bool {
		if metas[i].CreatedAt != metas[j].CreatedAt {
			return metas[i].CreatedAt > metas[j].CreatedAt
		}
		return metas[i].ID > metas[j].ID
	})
	return metas, nil
}

// Prune 按保留数裁剪历史快照：当前基线始终保留，历史最多保留 keep-1 条。
// 返回被删除的快照 id；磁盘删除失败会中止并返回已删除清单与错误。
func (s *Store) Prune(keep int) ([]string, error) {
	if keep < 1 {
		keep = DefaultBaselineKeep
	}
	if keep > MaxBaselineKeep {
		keep = MaxBaselineKeep
	}
	index, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	metas := append([]SnapshotMeta(nil), index.Snapshots...)
	sort.Slice(metas, func(i, j int) bool {
		if metas[i].CreatedAt != metas[j].CreatedAt {
			return metas[i].CreatedAt > metas[j].CreatedAt
		}
		return metas[i].ID > metas[j].ID
	})
	allowed := keep - 1
	if allowed < 0 {
		allowed = 0
	}
	removed := make([]string, 0)
	kept := make([]SnapshotMeta, 0, len(metas))
	for position, meta := range metas {
		if position < allowed {
			kept = append(kept, meta)
			continue
		}
		if err := os.Remove(s.snapshotPath(meta.ID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			index.Snapshots = kept
			_ = s.writeIndex(index)
			return removed, fmt.Errorf("删除旧快照 %s: %w", meta.ID, err)
		}
		removed = append(removed, meta.ID)
	}
	index.Snapshots = kept
	if err := s.writeIndex(index); err != nil {
		return removed, err
	}
	return removed, nil
}

// SnapshotExists 报告 id 是否对应当前基线或历史快照。
func (s *Store) SnapshotExists(id string) bool {
	if validateSnapshotID(id) != nil {
		return false
	}
	if _, err := s.LoadSnapshot(id); err != nil {
		return false
	}
	return true
}

// readIndex 读取历史索引；文件不存在返回空索引，损坏返回错误（不静默丢历史）。
func (s *Store) readIndex() (indexFile, error) {
	index := indexFile{Version: indexVersion, Snapshots: []SnapshotMeta{}}
	data, err := os.ReadFile(filepath.Join(s.ArchivesDir(), indexFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return index, nil
		}
		return index, fmt.Errorf("读取快照索引: %w", err)
	}
	if err := json.Unmarshal(data, &index); err != nil {
		return index, fmt.Errorf("快照索引损坏: %w", err)
	}
	if index.Version != indexVersion {
		return index, fmt.Errorf("快照索引版本不支持: %d", index.Version)
	}
	if index.Snapshots == nil {
		index.Snapshots = []SnapshotMeta{}
	}
	return index, nil
}

// writeIndex 原子写历史索引。
func (s *Store) writeIndex(index indexFile) error {
	if err := os.MkdirAll(s.ArchivesDir(), 0o700); err != nil {
		return fmt.Errorf("创建历史快照目录: %w", err)
	}
	index.Version = indexVersion
	if index.Snapshots == nil {
		index.Snapshots = []SnapshotMeta{}
	}
	if err := writeJSONAtomic(filepath.Join(s.ArchivesDir(), indexFileName), index); err != nil {
		return fmt.Errorf("写入快照索引: %w", err)
	}
	return nil
}

// snapshotPath 返回历史快照文件路径。
func (s *Store) snapshotPath(id string) string {
	return filepath.Join(s.ArchivesDir(), id+".json")
}

// readBaselineFile 读取并校验一份基线文件；不存在返回 ErrNoBaseline。
func readBaselineFile(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoBaseline
		}
		return nil, fmt.Errorf("读取基线文件: %w", err)
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("基线文件损坏: %w", err)
	}
	if baseline.Version != baselineVersion && baseline.Version != legacyBaselineVersion {
		return nil, fmt.Errorf("基线文件版本不支持: %d", baseline.Version)
	}
	if baseline.Entries == nil {
		baseline.Entries = []Entry{}
	}
	return &baseline, nil
}

// deriveBaselineID 给没有 id 的旧基线派生稳定 id：优先用 CreatedAt，解析失败用 legacy 前缀。
func deriveBaselineID(baseline *Baseline) string {
	if baseline.ID != "" {
		return baseline.ID
	}
	if parsed, err := time.Parse(time.RFC3339Nano, baseline.CreatedAt); err == nil {
		return "baseline-" + parsed.UTC().Format("20060102T150405.000000000Z")
	}
	return "baseline-legacy"
}

// newBaselineID 生成新的快照 id：baseline-<UTC 纳秒>；同一纳秒冲突时追加序号。
func newBaselineID(store *Store, now time.Time) string {
	base := "baseline-" + now.UTC().Format("20060102T150405.000000000Z")
	candidate := base
	for suffix := 2; ; suffix++ {
		if _, err := os.Stat(store.snapshotPath(candidate)); errors.Is(err, os.ErrNotExist) {
			if current, loadErr := store.Load(); loadErr != nil || current.ID != candidate {
				return candidate
			}
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

// validateSnapshotID 校验快照 id：只允许小写字母数字与 . -，禁止路径分隔与 ..。
func validateSnapshotID(id string) error {
	if id == "" || len(id) > 128 {
		return errors.New("基线快照 id 非法")
	}
	if strings.HasPrefix(id, ".") || strings.Contains(id, "..") || strings.ContainsAny(id, "/\\") {
		return errors.New("基线快照 id 非法")
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
		default:
			return errors.New("基线快照 id 非法")
		}
	}
	return nil
}

// metaFromBaseline 从完整基线提取元信息。
func metaFromBaseline(baseline *Baseline) SnapshotMeta {
	meta := SnapshotMeta{
		ID:          baseline.ID,
		CreatedAt:   baseline.CreatedAt,
		Note:        baseline.Note,
		Entries:     len(baseline.Entries),
		TotalBytes:  baseline.TotalBytes,
		LastCheckAt: baseline.LastCheckAt,
		LastCheckOK: baseline.LastCheckOK,
	}
	if len(baseline.Roots) > 0 {
		meta.Roots = append([]string{}, baseline.Roots...)
	}
	return meta
}

// upsertMeta 按 id 覆盖或追加元信息。
func upsertMeta(metas []SnapshotMeta, meta SnapshotMeta) []SnapshotMeta {
	for i, existing := range metas {
		if existing.ID == meta.ID {
			metas[i] = meta
			return metas
		}
	}
	return append(metas, meta)
}

// writeJSONAtomic 用同目录临时文件 + 0600 + fsync + rename 原子写 JSON。
func writeJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建目录: %w", err)
	}
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("设置权限: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("写入: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("刷盘: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("替换 %s: %w", path, err)
	}
	if dirFile, openErr := os.Open(dir); openErr == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}
