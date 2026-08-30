//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

func prepareDetached(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

func processExists(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	commandLine, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	return err == nil && len(commandLine) > 0
}

func signalProcess(pid int, force bool) error {
	signal := syscall.SIGTERM
	if force {
		signal = syscall.SIGKILL
	}
	return syscall.Kill(pid, signal)
}
