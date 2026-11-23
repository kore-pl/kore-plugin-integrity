package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoBackgroundTimers 是 G-19 的静态门禁：插件内不得出现任何周期定时源或 sleep 轮询。
// 定时扫描只能以「内核 scheduler 任务描述」的形式交给内核（integrity.schedule.set）。
func TestNoBackgroundTimers(t *testing.T) {
	forbidden := []string{"time.NewTicker(", "time.AfterFunc(", "time.Tick(", "time.Sleep("}
	checked := 0
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "bin", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		checked++
		for _, token := range forbidden {
			if strings.Contains(string(data), token) {
				t.Errorf("%s 出现被 G-19 禁止的周期/睡眠调用 %q", path, token)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("遍历源码: %v", err)
	}
	if checked == 0 {
		t.Fatal("未扫描到任何 .go 源文件，门禁形同虚设")
	}
}
