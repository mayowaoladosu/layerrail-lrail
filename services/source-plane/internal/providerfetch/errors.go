// Package providerfetch resolves and materializes exact provider commits without executing Git.
package providerfetch

import (
	"errors"
	"regexp"
)

var (
	ErrInvalidRequest         = errors.New("invalid provider fetch request")
	ErrProviderAuthentication = errors.New("provider authentication failed")
	ErrProviderUnavailable    = errors.New("provider is unavailable")
	ErrReferenceNotFound      = errors.New("provider commit was not found")
	ErrRepositoryPolicy       = errors.New("repository violates source policy")
	ErrSubmoduleUnsupported   = errors.New("repository submodule is not enabled by source policy")
	ErrLFSUnsupported         = errors.New("Git LFS object is not enabled by source policy")
	providerCommitPattern     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)
