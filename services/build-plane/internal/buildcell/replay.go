package buildcell

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrReplay = errors.New("build assignment replay rejected")

type Reservation struct {
	CellID        string
	BuildID       string
	Generation    uint64
	Nonce         string
	PayloadDigest string
	ExpiresAt     time.Time
}

type ReservationOutcome string

const (
	ReservationAccepted ReservationOutcome = "accepted"
	ReservationReplay   ReservationOutcome = "replay"
	ReservationStale    ReservationOutcome = "stale"
	ReservationConflict ReservationOutcome = "conflict"
)

type ReplayStore interface {
	Reserve(ctx context.Context, reservation Reservation) (ReservationOutcome, error)
}

type replayEntry struct {
	Generation    uint64 `json:"generation"`
	Nonce         string `json:"nonce"`
	PayloadDigest string `json:"payload_digest"`
}

type MemoryReplayStore struct {
	mu         sync.Mutex
	clock      func() time.Time
	maxEntries int
	builds     map[string]replayEntry
	nonces     map[string]bool
}

func NewMemoryReplayStore(clock func() time.Time, maxEntries int) (*MemoryReplayStore, error) {
	if clock == nil {
		clock = time.Now
	}
	if maxEntries < 1 || maxEntries > 1_000_000 {
		return nil, fmt.Errorf("%w: replay store capacity is invalid", ErrReplay)
	}
	return &MemoryReplayStore{
		clock: clock, maxEntries: maxEntries,
		builds: make(map[string]replayEntry), nonces: make(map[string]bool),
	}, nil
}

func (store *MemoryReplayStore) Reserve(ctx context.Context, reservation Reservation) (ReservationOutcome, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateReservation(reservation); err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !reservation.ExpiresAt.After(store.clock().UTC()) {
		return "", fmt.Errorf("%w: reservation is expired", ErrReplay)
	}
	return reserveReplayState(store.builds, store.nonces, store.maxEntries, reservation)
}

func reserveReplayState(builds map[string]replayEntry, nonces map[string]bool, maxEntries int, reservation Reservation) (ReservationOutcome, error) {
	buildKey := reservation.CellID + ":" + reservation.BuildID
	nonceKey := reservation.CellID + ":" + reservation.Nonce
	if existing, exists := builds[buildKey]; exists {
		if reservation.Generation < existing.Generation {
			return ReservationStale, nil
		}
		if reservation.Generation == existing.Generation {
			if reservation.Nonce == existing.Nonce && reservation.PayloadDigest == existing.PayloadDigest {
				return ReservationReplay, nil
			}
			return ReservationConflict, nil
		}
	}
	if nonces[nonceKey] {
		return ReservationConflict, nil
	}
	if len(builds) >= maxEntries || len(nonces) >= maxEntries {
		return "", fmt.Errorf("%w: replay store capacity exhausted", ErrReplay)
	}
	builds[buildKey] = replayEntry{
		Generation: reservation.Generation, Nonce: reservation.Nonce,
		PayloadDigest: reservation.PayloadDigest,
	}
	nonces[nonceKey] = true
	return ReservationAccepted, nil
}

func validateReservation(reservation Reservation) error {
	if err := validateID(reservation.CellID, "cell"); err != nil {
		return err
	}
	if err := validateID(reservation.BuildID, "bld"); err != nil {
		return err
	}
	if reservation.Generation == 0 || !noncePattern.MatchString(reservation.Nonce) || !digestPattern.MatchString(reservation.PayloadDigest) || reservation.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: reservation identity is invalid", ErrReplay)
	}
	return nil
}
