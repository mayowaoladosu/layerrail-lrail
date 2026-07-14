//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const xattrProbeName = "user.lrail.probe"

func requireXattrSupport(root string) error {
	probe, err := os.CreateTemp(root, ".lrail-xattr-probe-")
	if err != nil {
		return errors.New("create worker filesystem metadata probe")
	}
	path := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("close worker filesystem metadata probe")
	}
	defer os.Remove(path)

	value := []byte("required")
	if err := unix.Lsetxattr(path, xattrProbeName, value, 0); err != nil {
		return errors.New("worker state filesystem lacks required extended-attribute support")
	}
	defer unix.Lremovexattr(path, xattrProbeName)

	size, err := unix.Llistxattr(path, nil)
	if err != nil || size <= 0 || size > 64<<10 {
		return errors.New("worker state filesystem cannot list required extended attributes")
	}
	attributes := make([]byte, size)
	written, err := unix.Llistxattr(path, attributes)
	if err != nil || written <= 0 || !bytes.Contains(attributes[:written], []byte(xattrProbeName+"\x00")) {
		return errors.New("worker state filesystem did not retain the metadata probe")
	}

	size, err = unix.Lgetxattr(path, xattrProbeName, nil)
	if err != nil || size != len(value) {
		return errors.New("worker state filesystem cannot read required extended attributes")
	}
	actual := make([]byte, size)
	written, err = unix.Lgetxattr(path, xattrProbeName, actual)
	if err != nil || written != len(value) || !bytes.Equal(actual, value) {
		return errors.New("worker state filesystem changed the metadata probe")
	}
	return nil
}