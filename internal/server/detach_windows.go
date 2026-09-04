//go:build windows

package server

import (
	"os/exec"
	"syscall"
)

const createNoWindow = 0x08000000

// setDetached configura el proceso para que continue ejecutandose de forma
// independiente (sin ventana de consola) en Windows.
func setDetached(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNoWindow, HideWindow: true}
	return cmd
}
