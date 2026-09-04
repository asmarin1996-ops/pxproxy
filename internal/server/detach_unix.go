//go:build !windows

package server

import "os/exec"

// setDetached configura el proceso para que continue ejecutandose de forma
// independiente del proceso padre.
func setDetached(cmd *exec.Cmd) *exec.Cmd {
	_ = cmd
	return cmd
}
