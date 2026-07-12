// Package canonicaljson creates stable JSON bytes for digests and signatures.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrTrailingData = errors.New("canonical JSON input contains trailing data")

// Marshal normalizes a typed value through JSON and emits stable key ordering
// without presentation whitespace or HTML-specific escaping.
func Marshal(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal canonical JSON source: %w", err)
	}
	return Normalize(raw)
}

// Normalize parses exactly one JSON value with number preservation and emits a
// stable representation. Typed platform contracts use integer quantities only.
func Normalize(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode canonical JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, ErrTrailingData
		}
		return nil, fmt.Errorf("decode canonical JSON trailing data: %w", err)
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "")
	if err := encoder.Encode(value); err != nil {
		return nil, fmt.Errorf("encode canonical JSON: %w", err)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte("\n")), nil
}
