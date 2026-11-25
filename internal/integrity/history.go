package integrity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// 扫描历史布局（0.6.0 起）：
//
//	<state>/scans.json  最近 MaxScanHistory 次 check 的汇总（只记计数，不记逐文件路径）
//
// 为什么只记汇总：明细（每次扫描的几百行路径 + 指纹）会让落盘与内存随扫描次数线性膨胀
// （G-03），而"上次扫描是几点 / 改了几条 / 结论如何"才是换浏览器后真正需要的上下文；
// 逐文件明细仍由主壳前端按次留存（web/integrity.js 的 HISTORY_RUNS）。
// 体积上界：MaxScanHistory(20) × 单条约 200 字节 ≈ 4 KiB，可忽略。
const (
	// scanHistoryFileName 是扫描历史文件名，固定在插件状态目录下。
	scanHistoryFileName = "scans.json"
	// MaxScanHistory 是保留的扫描次数上限（最新在前）。
	MaxScanHistory = 20
	// scanHistoryVersion 是扫描历史文件 schema 版本。
	scanHistoryVersion = 1
)

// ScanRecord 是一次 check 的汇总记录（供 status.scan_history 消费）。
type ScanRecord struct {
	// CheckedAt 是本次比对时刻（与 check 结果的 checked_at 同一口径）。
	CheckedAt string `json:"checked_at"`
	// BaselineID 是本次比对用的基线快照 id。
	BaselineID string `json:"baseline_id"`
	// OK 是本次比对是否无差异。
	OK bool `json:"ok"`
	// Added / Removed / Modified 是三态计数，Unchanged 是未变化条目数。
	Added     int `json:"added"`
	Removed   int `json:"removed"`
	Modified  int `json:"modified"`
	Unchanged int `json:"unchanged"`
	// Skipped 是扫描期被跳过 / 告警的条目数（结论可能不完整）。
	Skipped int `json:"skipped"`
	// Truncated 表示结果被条目上限截断。
	Truncated bool `json:"truncated,omitempty"`
	// DurationMS 是本次 check 的墙钟毫秒数。
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// scanHistoryFile 是扫描历史的落盘形状。
type scanHistoryFile struct {
	Version int          `json:"version"`
	Runs    []ScanRecord `json:"runs"`
}

// scanRecordOf 从 check 结果提炼一条汇总记录。
func scanRecordOf(result CheckResult, baselineID string, durationMS int64) ScanRecord {
	return ScanRecord{
		CheckedAt:  result.CheckedAt,
		BaselineID: baselineID,
		OK:         result.OK,
		Added:      len(result.Added),
		Removed:    len(result.Removed),
		Modified:   len(result.Modified),
		Unchanged:  result.Unchanged,
		Skipped:    result.Summary.Skipped,
		Truncated:  result.Truncated,
		DurationMS: durationMS,
	}
}

// AppendScan 把一条扫描记录插到最前并按 MaxScanHistory 裁剪，原子落盘（0600）。
//
// 与基线索引不同，扫描历史是**辅助轨道**：文件损坏时按空处理并覆盖重写（自愈），
// 不让一条历史日志把 check / status 整个拖死；基线与索引仍然严格 fail-closed。
func (s *Store) AppendScan(rec ScanRecord) error {
	if s.dir == "" {
		return errors.New("KORE_STATE_DIR 未设置")
	}
	if rec.CheckedAt == "" {
		return errors.New("扫描记录缺少 checked_at")
	}
	runs := s.readScanHistory().Runs
	next := make([]ScanRecord, 0, len(runs)+1)
	next = append(next, rec)
	next = append(next, runs...)
	if len(next) > MaxScanHistory {
		next = next[:MaxScanHistory]
	}
	return s.writeScanHistory(scanHistoryFile{Version: scanHistoryVersion, Runs: next})
}

// ScanHistory 返回最近 MaxScanHistory 次扫描记录（最新在前）；文件不存在返回空数组。
func (s *Store) ScanHistory() ([]ScanRecord, error) {
	if s.dir == "" {
		return nil, errors.New("KORE_STATE_DIR 未设置")
	}
	data, err := os.ReadFile(filepath.Join(s.dir, scanHistoryFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []ScanRecord{}, nil
		}
		return nil, fmt.Errorf("读取扫描历史: %w", err)
	}
	var file scanHistoryFile
	if err := json.Unmarshal(data, &file); err != nil || file.Version != scanHistoryVersion {
		// 辅助轨道：损坏 / 版本不认识 → 按空处理，下一次 check 覆盖重写。
		return []ScanRecord{}, nil
	}
	if file.Runs == nil {
		return []ScanRecord{}, nil
	}
	return file.Runs, nil
}

// readScanHistory 读取扫描历史；任何异常都按空处理（见 AppendScan 注释）。
func (s *Store) readScanHistory() scanHistoryFile {
	file := scanHistoryFile{Version: scanHistoryVersion, Runs: []ScanRecord{}}
	data, err := os.ReadFile(filepath.Join(s.dir, scanHistoryFileName))
	if err != nil {
		return file
	}
	if err := json.Unmarshal(data, &file); err != nil || file.Version != scanHistoryVersion {
		return scanHistoryFile{Version: scanHistoryVersion, Runs: []ScanRecord{}}
	}
	if file.Runs == nil {
		file.Runs = []ScanRecord{}
	}
	return file
}

// writeScanHistory 原子写扫描历史。
func (s *Store) writeScanHistory(file scanHistoryFile) error {
	file.Version = scanHistoryVersion
	if file.Runs == nil {
		file.Runs = []ScanRecord{}
	}
	if err := writeJSONAtomic(filepath.Join(s.dir, scanHistoryFileName), file); err != nil {
		return fmt.Errorf("写入扫描历史: %w", err)
	}
	return nil
}
