package buildworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const MaxLogLineBytes = 64 * 1024

var redacted = []byte("[REDACTED]")

type logBuffer struct {
	contents []byte
	dropping bool
}

type Redactor struct {
	mu       sync.Mutex
	patterns [][]byte
	buffers  map[string]*logBuffer
}

func NewRedactor(secrets map[string][]byte) *Redactor {
	unique := make(map[[sha256.Size]byte][]byte)
	for _, value := range secrets {
		quoted := strconv.Quote(string(value))
		variants := [][]byte{
			append([]byte(nil), value...),
			[]byte(base64.StdEncoding.EncodeToString(value)),
			[]byte(base64.RawStdEncoding.EncodeToString(value)),
			[]byte(base64.URLEncoding.EncodeToString(value)),
			[]byte(base64.RawURLEncoding.EncodeToString(value)),
			[]byte(hex.EncodeToString(value)),
			[]byte(url.QueryEscape(string(value))),
			[]byte(strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`)),
		}
		for _, line := range bytes.FieldsFunc(value, func(character rune) bool { return character == '\r' || character == '\n' }) {
			variants = append(variants, append([]byte(nil), line...))
		}
		for _, variant := range variants {
			if len(variant) > 0 {
				unique[sha256.Sum256(variant)] = variant
			}
		}
	}
	patterns := make([][]byte, 0, len(unique))
	for _, pattern := range unique {
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(left, right int) bool { return len(patterns[left]) > len(patterns[right]) })
	return &Redactor{patterns: patterns, buffers: make(map[string]*logBuffer)}
}

func (redactor *Redactor) Close() {
	redactor.mu.Lock()
	defer redactor.mu.Unlock()
	for _, pattern := range redactor.patterns {
		zeroBytes(pattern)
	}
	for _, buffer := range redactor.buffers {
		zeroBytes(buffer.contents)
		buffer.contents = nil
	}
	redactor.patterns = nil
	redactor.buffers = nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (redactor *Redactor) Push(stream string, data []byte) []string {
	redactor.mu.Lock()
	defer redactor.mu.Unlock()
	buffer := redactor.buffers[stream]
	if buffer == nil {
		buffer = new(logBuffer)
		redactor.buffers[stream] = buffer
	}
	result := make([]string, 0)
	for len(data) > 0 {
		newline := bytes.IndexByte(data, '\n')
		if newline < 0 {
			if !buffer.dropping {
				if len(buffer.contents)+len(data) > MaxLogLineBytes {
					buffer.contents = nil
					buffer.dropping = true
					result = append(result, "[log line omitted: oversized]")
				} else {
					buffer.contents = append(buffer.contents, data...)
				}
			}
			break
		}
		chunk := data[:newline]
		data = data[newline+1:]
		if buffer.dropping {
			buffer.dropping = false
			buffer.contents = nil
			continue
		}
		if len(buffer.contents)+len(chunk) > MaxLogLineBytes {
			buffer.contents = nil
			result = append(result, "[log line omitted: oversized]")
			continue
		}
		buffer.contents = append(buffer.contents, chunk...)
		result = append(result, string(redactor.redact(buffer.contents)))
		buffer.contents = nil
	}
	return result
}

func (redactor *Redactor) Flush() map[string][]string {
	redactor.mu.Lock()
	defer redactor.mu.Unlock()
	result := make(map[string][]string)
	for stream, buffer := range redactor.buffers {
		if !buffer.dropping && len(buffer.contents) > 0 {
			result[stream] = []string{string(redactor.redact(buffer.contents))}
		}
	}
	redactor.buffers = make(map[string]*logBuffer)
	return result
}

func (redactor *Redactor) RedactString(value string) string {
	redactor.mu.Lock()
	defer redactor.mu.Unlock()
	return string(redactor.redact([]byte(value)))
}

func (redactor *Redactor) redact(value []byte) []byte {
	result := append([]byte(nil), value...)
	for _, pattern := range redactor.patterns {
		result = bytes.ReplaceAll(result, pattern, redacted)
	}
	return result
}

func streamKey(vertex string, stream int) string {
	return fmt.Sprintf("%s:%d", vertex, stream)
}
