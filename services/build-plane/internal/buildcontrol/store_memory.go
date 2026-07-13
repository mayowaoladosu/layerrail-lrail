package buildcontrol

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
)

const CurrentRunRecordVersion = 2

var runDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var runOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type MemoryRunStore struct {
	mu      sync.Mutex
	records map[string]RunRecord
}

func NewMemoryRunStore() *MemoryRunStore {
	return &MemoryRunStore{records: make(map[string]RunRecord)}
}

func (store *MemoryRunStore) Claim(ctx context.Context, request ClaimRequest) (ClaimOutcome, RunRecord, error) {
	if err := ctx.Err(); err != nil {
		return "", RunRecord{}, err
	}
	if err := validateClaim(request); err != nil {
		return "", RunRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, exists := store.records[request.BuildID]
	if !exists {
		record := newRunRecord(request)
		store.records[request.BuildID] = record
		return ClaimAccepted, record, nil
	}
	outcome, record := applyClaim(existing, request)
	if outcome == ClaimResumed {
		store.records[request.BuildID] = record
	}
	return outcome, record, nil
}

func (store *MemoryRunStore) Heartbeat(ctx context.Context, buildID, owner string, phase buildworker.Phase, attempt uint32, now time.Time, leaseTTL time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[buildID]
	if !exists || record.Owner != owner || record.Result.Terminal() || !validLeaseUpdate(phase, attempt, now, leaseTTL) {
		return fmt.Errorf("%w: run lease ownership or heartbeat is invalid", ErrController)
	}
	record.Phase = phase
	record.Attempt = attempt
	record.UpdatedAt = now.UTC()
	record.LeaseUntil = now.UTC().Add(leaseTTL)
	store.records[buildID] = record
	return nil
}

func (store *MemoryRunStore) Finish(ctx context.Context, buildID, owner string, result Result, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[buildID]
	if !exists || record.Owner != owner || validateTerminalResult(result, buildID, record.PayloadDigest) != nil || !terminalAllowedForRecord(record, result) || now.IsZero() {
		return fmt.Errorf("%w: terminal run result is invalid", ErrController)
	}
	record.Phase = result.Phase
	record.Attempt = result.Attempts
	record.Result = result
	record.UpdatedAt = now.UTC()
	record.LeaseUntil = time.Time{}
	store.records[buildID] = record
	return nil
}

func (store *MemoryRunStore) Lookup(ctx context.Context, buildID string) (RunRecord, bool, error) {
	if err := ctx.Err(); err != nil {
		return RunRecord{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[buildID]
	return record, exists, nil
}

func (store *MemoryRunStore) RequestCancel(ctx context.Context, buildID string, generation uint64, now time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validCancelRequest(buildID, generation, now) {
		return false, fmt.Errorf("%w: cancellation request is invalid", ErrController)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[buildID]
	if !exists || record.Generation != generation || record.Result.Terminal() {
		return false, nil
	}
	record.CancelRequested = true
	record.UpdatedAt = now.UTC()
	store.records[buildID] = record
	return true, nil
}

func validateClaim(request ClaimRequest) error {
	parsed, err := platformid.Parse(request.BuildID)
	if err != nil || parsed.Prefix() != "bld" || request.Generation == 0 || !runDigestPattern.MatchString(request.PayloadDigest) || !runOwnerPattern.MatchString(request.Owner) || request.Now.IsZero() ||
		request.LeaseTTL < time.Second || request.LeaseTTL > 5*time.Minute {
		return fmt.Errorf("%w: run claim is invalid", ErrController)
	}
	return nil
}

func newRunRecord(request ClaimRequest) RunRecord {
	return RunRecord{
		Version: CurrentRunRecordVersion, BuildID: request.BuildID, Generation: request.Generation,
		PayloadDigest: request.PayloadDigest, Owner: request.Owner, LeaseUntil: request.Now.UTC().Add(request.LeaseTTL),
		Phase: buildworker.PhaseAccepted, Attempt: 0, UpdatedAt: request.Now.UTC(),
		Result: Result{BuildID: request.BuildID, PayloadDigest: request.PayloadDigest, Phase: buildworker.PhaseAccepted, StartedAt: request.Now.UTC()},
	}
}

func applyClaim(existing RunRecord, request ClaimRequest) (ClaimOutcome, RunRecord) {
	if existing.Version != CurrentRunRecordVersion || existing.BuildID != request.BuildID || existing.Generation != request.Generation || existing.PayloadDigest != request.PayloadDigest {
		return ClaimConflict, existing
	}
	if existing.Result.Terminal() {
		return ClaimReplay, existing
	}
	if existing.LeaseUntil.After(request.Now.UTC()) && existing.Owner != request.Owner {
		return ClaimInProgress, existing
	}
	existing.Owner = request.Owner
	existing.LeaseUntil = request.Now.UTC().Add(request.LeaseTTL)
	existing.UpdatedAt = request.Now.UTC()
	return ClaimResumed, existing
}

func validCancelRequest(buildID string, generation uint64, now time.Time) bool {
	parsed, err := platformid.Parse(buildID)
	return err == nil && parsed.Prefix() == "bld" && generation > 0 && !now.IsZero()
}

func validLeaseUpdate(phase buildworker.Phase, attempt uint32, now time.Time, leaseTTL time.Duration) bool {
	return validRunPhase(phase, false) && attempt <= DefaultMaxAttempts && !now.IsZero() && leaseTTL >= time.Second && leaseTTL <= 5*time.Minute
}

func validateRunRecord(record RunRecord) error {
	parsed, err := platformid.Parse(record.BuildID)
	if err != nil || parsed.Prefix() != "bld" || record.Version != CurrentRunRecordVersion || record.Generation == 0 ||
		!runDigestPattern.MatchString(record.PayloadDigest) || !runOwnerPattern.MatchString(record.Owner) || !validRunPhase(record.Phase, record.Result.Terminal()) ||
		record.Attempt > DefaultMaxAttempts || record.UpdatedAt.IsZero() || record.Result.BuildID != record.BuildID || record.Result.PayloadDigest != record.PayloadDigest || record.Result.Replay {
		return fmt.Errorf("%w: durable run record identity is invalid", ErrController)
	}
	if record.Result.Terminal() {
		if !record.LeaseUntil.IsZero() || record.Result.Phase != record.Phase || record.Result.Attempts != record.Attempt || validateTerminalResult(record.Result, record.BuildID, record.PayloadDigest) != nil || !terminalAllowedForRecord(record, record.Result) {
			return fmt.Errorf("%w: durable terminal run record is invalid", ErrController)
		}
		return nil
	}
	if record.LeaseUntil.IsZero() || record.Result.Phase != buildworker.PhaseAccepted || record.Result.StartedAt.IsZero() || !record.Result.FinishedAt.IsZero() {
		return fmt.Errorf("%w: durable active run record is invalid", ErrController)
	}
	return nil
}

func terminalAllowedForRecord(record RunRecord, result Result) bool {
	return !record.CancelRequested || result.Phase == buildworker.PhaseCanceled || result.Phase == buildworker.PhaseQuarantined
}

func validateTerminalResult(result Result, buildID, payloadDigest string) error {
	if !result.Terminal() || result.BuildID != buildID || result.PayloadDigest != payloadDigest || result.Attempts > DefaultMaxAttempts || result.Replay ||
		!runDigestPattern.MatchString(result.LogsDigest) || result.StartedAt.IsZero() || result.FinishedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) || result.Cleanup.BuildID != buildID {
		return fmt.Errorf("%w: terminal result identity is invalid", ErrController)
	}
	clean := result.Cleanup.Status == buildworker.CleanupClean && len(result.Cleanup.Residue) == 0 && result.Cleanup.QuarantineReason == ""
	quarantined := result.Cleanup.Status == buildworker.CleanupQuarantined && (len(result.Cleanup.Residue) > 0 || result.Cleanup.QuarantineReason != "")
	switch result.Phase {
	case buildworker.PhaseComplete:
		workerClean := result.Worker.Cleanup.BuildID == buildID && result.Worker.Cleanup.Status == buildworker.CleanupClean && len(result.Worker.Cleanup.Residue) == 0 && result.Worker.Cleanup.QuarantineReason == ""
		if !clean || result.ErrorCode != "" || result.Attempts == 0 || result.WorkerIdentity == "" || result.Worker.BuildID != buildID ||
			result.Worker.Attempt != result.Attempts || result.Worker.Phase != buildworker.PhaseComplete || !workerClean || !runDigestPattern.MatchString(result.Worker.LogsDigest) ||
			result.Worker.Cache.Hits < 0 || result.Worker.Cache.Misses < 0 || len(result.Worker.Outputs) == 0 {
			return fmt.Errorf("%w: successful terminal result lacks immutable output or cleanup proof", ErrController)
		}
		outputNames := make(map[string]struct{}, len(result.Worker.Outputs))
		for _, output := range result.Worker.Outputs {
			_, duplicate := outputNames[output.Name]
			if output.Name == "" || (output.Kind != "oci_image" && output.Kind != "static_bundle") || output.ArtifactRef == "" ||
				!runDigestPattern.MatchString(output.ArtifactDigest) || output.ArtifactSize <= 0 || !runDigestPattern.MatchString(output.ConfigDigest) || duplicate || !validOutputContentIdentity(output) {
				return fmt.Errorf("%w: successful terminal output identity is invalid", ErrController)
			}
			outputNames[output.Name] = struct{}{}
		}
	case buildworker.PhaseQuarantined:
		if !quarantined || result.ErrorCode == "" {
			return fmt.Errorf("%w: quarantined terminal result lacks residue proof", ErrController)
		}
	case buildworker.PhaseFailed, buildworker.PhaseCanceled:
		if !clean || result.ErrorCode == "" {
			return fmt.Errorf("%w: failed terminal result lacks clean cleanup proof", ErrController)
		}
	default:
		return fmt.Errorf("%w: terminal result phase is invalid", ErrController)
	}
	return nil
}

func validRunPhase(phase buildworker.Phase, terminal bool) bool {
	if terminal {
		return phase == buildworker.PhaseComplete || phase == buildworker.PhaseFailed || phase == buildworker.PhaseCanceled || phase == buildworker.PhaseQuarantined
	}
	switch phase {
	case buildworker.PhaseAccepted, buildworker.PhaseResolving, buildworker.PhaseAllocating, buildworker.PhaseMaterializing,
		buildworker.PhaseSolving, buildworker.PhaseExporting, buildworker.PhaseRetrying, buildworker.PhaseCanceling, buildworker.PhaseCleaning:
		return true
	default:
		return false
	}
}
