//go:build unix

package integrity

import (
	"os"
	"syscall"
)

// ownerIDs 从 Unix stat 取 uid/gid；取不到时回退 0 并由调用方按元数据解读。
func ownerIDs(info os.FileInfo) (int, int) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0
	}
	return int(stat.Uid), int(stat.Gid)
}
