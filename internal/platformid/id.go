// Package platformid creates and validates prefixed UUIDv7 resource identifiers.
package platformid

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const uuidTextLength = 36

var (
	// ErrInvalid identifies an identifier that violates the public ID contract.
	ErrInvalid      = errors.New("invalid resource identifier")
	allowedPrefixes = map[string]struct{}{
		"acct": {}, "org": {}, "mbr": {}, "inv": {}, "prj": {}, "env": {},
		"svc": {}, "src": {}, "snp": {}, "bld": {}, "rev": {}, "dep": {},
		"rel": {}, "op": {}, "dom": {}, "crt": {}, "rte": {}, "add": {},
		"att": {}, "bkp": {}, "rst": {}, "sch": {}, "wh": {}, "whd": {},
		"key": {}, "evt": {}, "tgt": {}, "edg": {}, "cell": {}, "pop": {},
		"use": {}, "sec": {}, "var": {}, "vol": {}, "job": {}, "run": {},
		"pol": {}, "inc": {}, "ses": {}, "tok": {},
		"upl": {},
	}
)

// ID is a validated prefixed UUIDv7 value.
type ID string

// New returns a UUIDv7 ID using the system clock and cryptographic randomness.
func New(prefix string) (ID, error) {
	return NewAt(prefix, time.Now().UTC(), rand.Reader)
}

// NewAt creates a UUIDv7 ID with injectable time and randomness for deterministic tests.
func NewAt(prefix string, now time.Time, randomness io.Reader) (ID, error) {
	if _, ok := allowedPrefixes[prefix]; !ok {
		return "", fmt.Errorf("%w: unsupported prefix %q", ErrInvalid, prefix)
	}
	if randomness == nil {
		return "", fmt.Errorf("%w: randomness source is nil", ErrInvalid)
	}
	milliseconds := now.UnixMilli()
	if milliseconds < 0 || milliseconds > 1<<48-1 {
		return "", fmt.Errorf("%w: timestamp is outside UUIDv7 range", ErrInvalid)
	}

	var raw [16]byte
	if _, err := io.ReadFull(randomness, raw[:]); err != nil {
		return "", fmt.Errorf("read UUIDv7 randomness: %w", err)
	}
	raw[0] = byte(milliseconds >> 40)
	raw[1] = byte(milliseconds >> 32)
	raw[2] = byte(milliseconds >> 24)
	raw[3] = byte(milliseconds >> 16)
	raw[4] = byte(milliseconds >> 8)
	raw[5] = byte(milliseconds)
	raw[6] = 0x70 | (raw[6] & 0x0f)
	raw[8] = 0x80 | (raw[8] & 0x3f)

	uuid := fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(raw[0:4]),
		binary.BigEndian.Uint16(raw[4:6]),
		binary.BigEndian.Uint16(raw[6:8]),
		binary.BigEndian.Uint16(raw[8:10]),
		raw[10:16],
	)
	return ID(prefix + "_" + uuid), nil
}

// Parse validates a prefixed canonical lowercase UUIDv7 value.
func Parse(value string) (ID, error) {
	prefix, uuid, ok := strings.Cut(value, "_")
	if !ok {
		return "", fmt.Errorf("%w: prefix separator is missing", ErrInvalid)
	}
	if _, allowed := allowedPrefixes[prefix]; !allowed {
		return "", fmt.Errorf("%w: unsupported prefix %q", ErrInvalid, prefix)
	}
	if len(uuid) != uuidTextLength || uuid != strings.ToLower(uuid) {
		return "", fmt.Errorf("%w: UUID must be canonical lowercase text", ErrInvalid)
	}
	if uuid[8] != '-' || uuid[13] != '-' || uuid[18] != '-' || uuid[23] != '-' {
		return "", fmt.Errorf("%w: UUID separators are not canonical", ErrInvalid)
	}
	compact := strings.ReplaceAll(uuid, "-", "")
	var raw [16]byte
	if _, err := hex.Decode(raw[:], []byte(compact)); err != nil {
		return "", fmt.Errorf("%w: malformed UUID: %v", ErrInvalid, err)
	}
	if raw[6]>>4 != 7 {
		return "", fmt.Errorf("%w: UUID version is not 7", ErrInvalid)
	}
	if raw[8]&0xc0 != 0x80 {
		return "", fmt.Errorf("%w: UUID variant is not RFC 9562", ErrInvalid)
	}
	canonical := fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	if uuid != canonical {
		return "", fmt.Errorf("%w: UUID is not canonical", ErrInvalid)
	}
	return ID(value), nil
}

// Prefix returns the immutable resource type prefix.
func (id ID) Prefix() string {
	prefix, _, _ := strings.Cut(string(id), "_")
	return prefix
}

// Time returns the millisecond timestamp encoded by UUIDv7.
func (id ID) Time() (time.Time, error) {
	parsed, err := Parse(string(id))
	if err != nil {
		return time.Time{}, err
	}
	_, uuid, _ := strings.Cut(string(parsed), "_")
	compact := strings.ReplaceAll(uuid[:13], "-", "")
	milliseconds, err := strconv.ParseInt(compact, 16, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse UUIDv7 timestamp: %w", err)
	}
	return time.UnixMilli(milliseconds).UTC(), nil
}
