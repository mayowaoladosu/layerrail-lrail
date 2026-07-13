package main

import "testing"

func TestOptionalStrictBool(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		fallback bool
		expected bool
		invalid  bool
	}{
		{name: "default true", fallback: true, expected: true},
		{name: "default false", fallback: false, expected: false},
		{name: "explicit true", value: "true", expected: true},
		{name: "explicit false", value: "false", fallback: true, expected: false},
		{name: "reject shorthand", value: "1", invalid: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("LRAIL_TEST_BOOL", test.value)
			actual, err := optionalStrictBool("LRAIL_TEST_BOOL", test.fallback)
			if (err != nil) != test.invalid || (!test.invalid && actual != test.expected) {
				t.Fatalf("optionalStrictBool() = %t, %v", actual, err)
			}
		})
	}
}
