package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseS3PrefixRejectsAuthorityAndPathConfusion(t *testing.T) {
	t.Parallel()
	valid, err := parseS3Prefix("s3://lrail-build/cell-a/inputs")
	if err != nil || valid.bucket != "lrail-build" || valid.path != "cell-a/inputs" {
		t.Fatalf("parseS3Prefix valid: %#v err=%v", valid, err)
	}
	for _, value := range []string{
		"https://lrail-build/cell-a", "s3://access:secret@lrail-build/cell-a", "s3://lrail-build/cell-a/../other",
		"s3://lrail-build/cell-a?version=1", "s3://lrail-build", "s3:///cell-a", "s3://lrail-build/cell-a//input",
	} {
		if _, err := parseS3Prefix(value); err == nil {
			t.Fatalf("expected S3 prefix rejection for %q", value)
		}
	}
}

func TestLoadStrictJSONRejectsUnknownAndTrailingData(t *testing.T) {
	t.Parallel()
	type config struct {
		Version int `json:"version"`
	}
	directory := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return path
	}
	var value config
	if err := loadStrictJSON(write("valid.json", `{"version":1}`), &value); err != nil || value.Version != 1 {
		t.Fatalf("load valid: value=%#v err=%v", value, err)
	}
	for name, contents := range map[string]string{
		"unknown.json":  `{"version":1,"secret":"forbidden"}`,
		"trailing.json": `{"version":1}{"version":2}`,
		"empty.json":    ``,
	} {
		if err := loadStrictJSON(write(name, contents), &config{}); err == nil {
			t.Fatalf("expected strict JSON rejection for %s", name)
		}
	}
}
