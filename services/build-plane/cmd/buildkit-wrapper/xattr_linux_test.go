//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRequireXattrSupportRoundTripsAndRemovesProbe(t *testing.T) {
	root := t.TempDir()
	if err := requireXattrSupport(root); err != nil {
		t.Fatalf("requireXattrSupport: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(root, ".lrail-xattr-probe-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("metadata probe residue = %v, %v", matches, err)
	}
}

func TestRequireXattrSupportRejectsMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	if err := requireXattrSupport(root); err == nil {
		t.Fatal("requireXattrSupport accepted a missing state root")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("missing root was created: %v", err)
	}
}