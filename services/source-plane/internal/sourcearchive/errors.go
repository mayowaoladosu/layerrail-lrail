package sourcearchive

import (
	"errors"
	"fmt"
)

var (
	ErrArchiveSize      = errors.New("source archive size violates policy")
	ErrArchiveDigest    = errors.New("source archive digest mismatch")
	ErrArchiveFormat    = errors.New("source archive format is unsafe")
	ErrEntryLimit       = errors.New("source archive entry limit exceeded")
	ErrExpandedSize     = errors.New("source archive expanded size limit exceeded")
	ErrCompressionRatio = errors.New("source archive compression ratio exceeded")
	ErrPathUnsafe       = errors.New("source archive path is unsafe")
	ErrEntryType        = errors.New("source archive entry type is unsafe")
	ErrDuplicatePath    = errors.New("source archive contains colliding paths")
	ErrSecretMaterial   = errors.New("source archive contains secret material")
	ErrMetadataInvalid  = errors.New("source metadata is invalid")
	ErrPolicyInvalid    = errors.New("source archive policy is invalid")
)

type ValidationError struct {
	Kind error
	Path string
	Info string
}

func (e *ValidationError) Error() string {
	message := e.Kind.Error()
	if e.Path != "" {
		message += fmt.Sprintf(" at %q", e.Path)
	}
	if e.Info != "" {
		message += ": " + e.Info
	}
	return message
}

func (e *ValidationError) Unwrap() error { return e.Kind }
