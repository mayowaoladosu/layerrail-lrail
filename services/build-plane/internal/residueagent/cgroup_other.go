//go:build !linux

package residueagent

import "context"

func killCgroupProcesses(context.Context, string) error {
	return nil
}
