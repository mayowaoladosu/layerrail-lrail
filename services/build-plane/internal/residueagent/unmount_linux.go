//go:build linux

package residueagent

import "golang.org/x/sys/unix"

func unmountPath(target string) error {
	return unix.Unmount(target, unix.MNT_DETACH)
}
