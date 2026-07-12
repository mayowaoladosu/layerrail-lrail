package platformid

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewAtRoundTripAndOrdering(t *testing.T) {
	t.Parallel()
	firstTime := time.Date(2026, 7, 12, 20, 0, 0, 123_000_000, time.UTC)
	first, err := NewAt("prj", firstTime, bytes.NewReader(bytes.Repeat([]byte{0x11}, 16)))
	if err != nil {
		t.Fatalf("NewAt first: %v", err)
	}
	second, err := NewAt("prj", firstTime.Add(time.Millisecond), bytes.NewReader(bytes.Repeat([]byte{0x00}, 16)))
	if err != nil {
		t.Fatalf("NewAt second: %v", err)
	}
	if first >= second {
		t.Fatalf("UUIDv7 text should sort chronologically: %q >= %q", first, second)
	}
	parsed, err := Parse(string(first))
	if err != nil || parsed != first {
		t.Fatalf("Parse(%q) = %q, %v", first, parsed, err)
	}
	gotTime, err := first.Time()
	if err != nil {
		t.Fatalf("Time: %v", err)
	}
	if !gotTime.Equal(firstTime) {
		t.Fatalf("Time = %s, want %s", gotTime, firstTime)
	}
	if first.Prefix() != "prj" {
		t.Fatalf("Prefix = %q, want prj", first.Prefix())
	}
}

func TestNewAtRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	if _, err := NewAt("unknown", time.Now(), bytes.NewReader(make([]byte, 16))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsupported prefix error = %v", err)
	}
	if _, err := NewAt("prj", time.UnixMilli(-1), bytes.NewReader(make([]byte, 16))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("negative timestamp error = %v", err)
	}
	if _, err := NewAt("prj", time.Now(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil randomness error = %v", err)
	}
	if _, err := NewAt("prj", time.Now(), bytes.NewReader(nil)); err == nil {
		t.Fatal("short randomness unexpectedly succeeded")
	}
}

func TestParseRejectsNonCanonicalOrWrongVersion(t *testing.T) {
	t.Parallel()
	cases := []string{
		"missing",
		"wat_019b01da-7e31-7000-8000-000000000001",
		"prj_019B01DA-7E31-7000-8000-000000000001",
		"prj_019b01da-7e31-6000-8000-000000000001",
		"prj_019b01da-7e31-7000-0000-000000000001",
		"prj_019b01da-7e31-7000-8000-00000000001z",
		"prj_019b01da7e31-7000-8000-000000000001",
	}
	for _, value := range cases {
		value := value
		t.Run(strings.ReplaceAll(value, "/", "_"), func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(value); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%q) error = %v", value, err)
			}
		})
	}
}
