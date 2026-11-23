package fault_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/pengtang1024/kore-plugin-integrity/internal/integrity"
	"github.com/pengtang1024/kore/pkg/pluginapi"
)

// scheduleSetRequest 是 integrity.schedule.set 的最简入参（其余字段取默认值）。
type scheduleSetRequest struct {
	Schedule string `json:"schedule,omitempty"`
}

// TestScheduleGetCorruptNotSilent schedule.json 写坏时 schedule.get 必须报错，
// 绝不能回"0 条任务"——用户会以为根本没排过扫描，实际是配置坏了、扫描不会跑。
//
// 「文件不存在」与「文件损坏」是两种结局，必须可区分：
// 前者是合法的"没排任务"，后者必须显式失败。
func TestScheduleGetCorruptNotSilent(t *testing.T) {
	fixture := newFaultFixture(t, nil)
	schedulePath := filepath.Join(fixture.state, "schedule.json")

	// 对照：文件不存在 = 真的没排任务，合法空集且不报错。
	empty := callOK[integrity.ScheduleGetResult](t, fixture.service, "schedule.get", nil)
	if empty.Count != 0 || len(empty.Records) != 0 {
		t.Fatalf("未排任务时 records=%d count=%d，期望空集", len(empty.Records), empty.Count)
	}

	// 故障：文件损坏必须显式失败，不能静默当成空计划。
	if err := os.WriteFile(schedulePath, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("写坏 schedule.json: %v", err)
	}
	perr := callFault(t, fixture.service, "schedule.get", nil)
	if perr.Code != pluginapi.E_INTERNAL {
		t.Fatalf("code=%s，期望 E_INTERNAL（损坏必须报错，不得静默返回空计划）", perr.Code)
	}
	t.Logf("损坏文件显式失败: %s %s", perr.Code, perr.Message)
	if _, err := os.Stat(schedulePath); err != nil {
		t.Fatalf("读取失败不应删除损坏文件（要留给用户/运维排查）: %v", err)
	}
}

// TestScheduleSetFault 覆盖 schedule.set 的两类故障：
//
//  1. schedule.json 已损坏：必须失败且**不改写**该文件——静默覆盖等于把用户配置丢掉；
//  2. 状态目录不可写：必须回 E_INTERNAL，不能回 saved=true，也不能留下半成品。
func TestScheduleSetFault(t *testing.T) {
	t.Run("schedule.json 损坏时不覆盖", func(t *testing.T) {
		fixture := newFaultFixture(t, map[string]string{"a.txt": "alpha"})
		baselineOK(t, fixture.service, []string{fixture.root})
		schedulePath := filepath.Join(fixture.state, "schedule.json")
		corrupt := []byte("{broken")
		if err := os.WriteFile(schedulePath, corrupt, 0o600); err != nil {
			t.Fatalf("写坏 schedule.json: %v", err)
		}

		perr := callFault(t, fixture.service, "schedule.set", scheduleSetRequest{Schedule: "0 4 * * *"})
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("code=%s，期望 E_INTERNAL（读不到旧描述就不能覆盖）", perr.Code)
		}
		after, err := os.ReadFile(schedulePath)
		if err != nil {
			t.Fatalf("失败后读 schedule.json: %v", err)
		}
		if !bytes.Equal(corrupt, after) {
			t.Fatalf("失败的 schedule.set 覆盖了损坏文件（用户配置被静默丢弃）: after=%q", string(after))
		}
	})

	t.Run("状态目录不可写时不谎报 saved", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root 无视目录权限，跳过权限用例")
		}
		fixture := newFaultFixture(t, map[string]string{"a.txt": "alpha"})
		baselineOK(t, fixture.service, []string{fixture.root})
		schedulePath := filepath.Join(fixture.state, "schedule.json")
		if _, err := os.Stat(schedulePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("起点不干净：schedule.json 已存在 err=%v", err)
		}

		if err := os.Chmod(fixture.state, 0o500); err != nil {
			t.Fatalf("chmod 状态目录: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(fixture.state, 0o700) })

		perr := callFault(t, fixture.service, "schedule.set", scheduleSetRequest{Schedule: "0 4 * * *"})
		if perr.Code != pluginapi.E_INTERNAL {
			t.Fatalf("code=%s，期望 E_INTERNAL（落盘失败必须显式失败）", perr.Code)
		}
		t.Logf("落盘失败显式报错: %s %s", perr.Code, perr.Message)

		if err := os.Chmod(fixture.state, 0o700); err != nil {
			t.Fatalf("恢复状态目录权限: %v", err)
		}
		if _, err := os.Stat(schedulePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("失败的 schedule.set 落下了半成品 schedule.json err=%v", err)
		}
	})
}
