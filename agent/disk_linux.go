//go:build linux

package main

import "syscall"

func diskStats(path string) (int64, int64) {
	var stats syscall.Statfs_t
	if err := syscall.Statfs(path, &stats); err != nil {
		return 0, 0
	}
	total := int64(stats.Blocks) * int64(stats.Bsize)
	available := int64(stats.Bavail) * int64(stats.Bsize)
	return total, total - available
}
