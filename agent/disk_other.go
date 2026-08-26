//go:build !linux

package main

func diskStats(string) (int64, int64) {
	return 0, 0
}
