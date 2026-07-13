//go:build !linux

package residueagent

import "errors"

func unmountPath(string) error {
	return errors.New("unmount is unsupported on this platform")
}
