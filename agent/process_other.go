//go:build !linux

package main

import (
	"errors"
	"os/exec"
)

func prepareDetached(_ *exec.Cmd) {}

func processExists(_ int) bool { return false }

func signalProcess(_ int, _ bool) error {
	return errors.New("standalone process control requires Linux")
}
