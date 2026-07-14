//go:build !linux

package main

import "errors"

func requireXattrSupport(string) error {
	return errors.New("strict worker filesystem validation requires Linux")
}