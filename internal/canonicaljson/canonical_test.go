package canonicaljson

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestNormalizeSortsKeysAndPreservesIntegerNumbers(t *testing.T) {
	t.Parallel()
	input := []byte(` { "z": 9007199254740993, "a": [true, "<safe>"] } `)
	got, err := Normalize(input)
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := []byte(`{"a":[true,"<safe>"],"z":9007199254740993}`)
	if !bytes.Equal(got, want) {
		t.Fatalf("Normalize = %s, want %s", got, want)
	}
}

func TestMarshalIsStableAcrossMapInsertionOrder(t *testing.T) {
	t.Parallel()
	first, err := Marshal(map[string]any{"b": 2, "a": 1})
	if err != nil {
		t.Fatalf("Marshal first: %v", err)
	}
	second, err := Marshal(map[string]any{"a": 1, "b": 2})
	if err != nil {
		t.Fatalf("Marshal second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("canonical maps differ: %s != %s", first, second)
	}
}

func TestNormalizeRejectsInvalidAndTrailingJSON(t *testing.T) {
	t.Parallel()
	if _, err := Normalize([]byte(`{"a":`)); err == nil {
		t.Fatal("invalid JSON unexpectedly succeeded")
	}
	if _, err := Normalize([]byte(`{} {}`)); !errors.Is(err, ErrTrailingData) {
		t.Fatalf("trailing JSON error = %v", err)
	}
	if _, err := Marshal(math.Inf(1)); err == nil {
		t.Fatal("unsupported float unexpectedly succeeded")
	}
}
