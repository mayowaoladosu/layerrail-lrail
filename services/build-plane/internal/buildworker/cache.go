package buildworker

import (
	"context"
	"errors"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
	"github.com/moby/buildkit/client"
)

type RejectingCacheProvider struct{}

func (RejectingCacheProvider) Acquire(_ context.Context, lock llbcompiler.DefinitionLock, _, _ string, _ uint32) (CacheLease, error) {
	if len(lock.Caches) != 0 {
		return nil, errors.New("signed cache capabilities have no configured backend")
	}
	return emptyCacheLease{}, nil
}

type emptyCacheLease struct{}

func (emptyCacheLease) Imports() []client.CacheOptionsEntry { return []client.CacheOptionsEntry{} }
func (emptyCacheLease) Exports() []client.CacheOptionsEntry { return []client.CacheOptionsEntry{} }
func (emptyCacheLease) Complete(bool) error                 { return nil }
