//go:build !unix

package integrity

import "os"

// ownerIDs 在非 Unix 平台无 uid/gid 语义，统一返回 0（Tier B 降级，不伪造数据）。
func ownerIDs(os.FileInfo) (int, int) {
	return 0, 0
}
