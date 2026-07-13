//go:build windows

package buildworker

import "os"

func terminateProcess(process *os.Process) error {
	return process.Kill()
}
