package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// baselineFileName 是基线文件名，固定在插件状态目录下。
const baselineFileName = "baseline.json"

// baselineVersion 是基线文件 schema 版本；结构变化时递增。
const baselineVersion = 1

// ErrNoBaseline 表示状态目录中还没有基线。
var ErrNoBaseline = errors.New("尚未建立完整性基线")

// Baseline 是落盘的基线快照。基线是快照语义：再次 baseline 会整体覆盖。
type Baseline struct {
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

// Store 管理 <state>/baseline.json 的读写。
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

// Path 返回基线文件绝对路径。
func (s *Store) Path() string {
	if s.dir == "" {
		return ""
	}
	return filepath.Join(s.dir, baselineFileName)
}

// Load 读取基线：文件不存在返回 ErrNoBaseline，内容损坏返回包装错误。
func (s *Store) Load() (*Baseline, error) {
	if s.dir == "" {
		return nil, errors.New("KORE_STATE_DIR 未设置")
	}
	data, err := os.ReadFile(s.Path())
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
	if baseline.Version != baselineVersion {
		return nil, fmt.Errorf("基线文件版本不支持: %d", baseline.Version)
	}
	return &baseline, nil
}

// Save 原子写入基线：临时文件 + fsync + rename，权限 0600。
func (s *Store) Save(baseline *Baseline) error {
	if s.dir == "" {
		return errors.New("KORE_STATE_DIR 未设置")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("创建状态目录: %w", err)
	}
	payload, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化基线: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("创建临时文件: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("设置基线权限: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		return fmt.Errorf("写入基线: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("刷盘基线: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭基线临时文件: %w", err)
	}
	if err := os.Rename(tmpName, s.Path()); err != nil {
		return fmt.Errorf("替换基线文件: %w", err)
	}
	// 目录 fsync：保证 rename 之后崩溃也能看到新文件。
	dir, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("打开状态目录: %w", err)
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("刷盘状态目录: %w", err)
	}
	return nil
}
