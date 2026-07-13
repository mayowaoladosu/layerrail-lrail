package buildcontrol

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildsupply"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

type attemptExecution struct {
	result buildworker.Result
	err    error
}

const (
	DefaultMaxAttempts    = 3
	DefaultLeaseTTL       = 30 * time.Second
	DefaultCancelGrace    = 15 * time.Second
	DefaultForceTimeout   = 15 * time.Second
	DefaultReleaseTimeout = 30 * time.Second
	DefaultRevokeTimeout  = 15 * time.Second
)

type Options struct {
	Verifier       *buildcell.Verifier
	Replay         buildcell.ReplayStore
	Runs           RunStore
	Artifacts      buildcell.ArtifactStore
	Capabilities   CapabilityBroker
	Workers        WorkerAllocator
	Clock          func() time.Time
	Owner          func() (string, error)
	MaxAttempts    uint32
	LeaseTTL       time.Duration
	CancelGrace    time.Duration
	ForceTimeout   time.Duration
	ReleaseTimeout time.Duration
	RevokeTimeout  time.Duration
	RetryDelay     func(attempt uint32) time.Duration
}

type Controller struct {
	verifier       *buildcell.Verifier
	replay         buildcell.ReplayStore
	runs           RunStore
	artifacts      buildcell.ArtifactStore
	capabilities   CapabilityBroker
	workers        WorkerAllocator
	clock          func() time.Time
	owner          func() (string, error)
	maxAttempts    uint32
	leaseTTL       time.Duration
	cancelGrace    time.Duration
	forceTimeout   time.Duration
	releaseTimeout time.Duration
	revokeTimeout  time.Duration
	retryDelay     func(uint32) time.Duration
}

func New(options Options) (*Controller, error) {
	if options.Verifier == nil || options.Replay == nil || options.Runs == nil || options.Artifacts == nil || options.Capabilities == nil || options.Workers == nil {
		return nil, fmt.Errorf("%w: controller dependencies are incomplete", ErrController)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Owner == nil {
		options.Owner = randomOwner
	}
	if options.MaxAttempts == 0 {
		options.MaxAttempts = DefaultMaxAttempts
	}
	if options.LeaseTTL == 0 {
		options.LeaseTTL = DefaultLeaseTTL
	}
	if options.CancelGrace == 0 {
		options.CancelGrace = DefaultCancelGrace
	}
	if options.ForceTimeout == 0 {
		options.ForceTimeout = DefaultForceTimeout
	}
	if options.ReleaseTimeout == 0 {
		options.ReleaseTimeout = DefaultReleaseTimeout
	}
	if options.RevokeTimeout == 0 {
		options.RevokeTimeout = DefaultRevokeTimeout
	}
	if options.RetryDelay == nil {
		options.RetryDelay = func(attempt uint32) time.Duration { return time.Duration(1<<min(attempt, 5)) * time.Second }
	}
	if options.MaxAttempts < 1 || options.MaxAttempts > 5 || options.LeaseTTL < time.Second || options.LeaseTTL > 5*time.Minute ||
		options.CancelGrace < time.Millisecond || options.CancelGrace > time.Minute || options.ForceTimeout < time.Millisecond || options.ForceTimeout > time.Minute ||
		options.ReleaseTimeout < time.Millisecond || options.ReleaseTimeout > time.Minute || options.RevokeTimeout < time.Millisecond || options.RevokeTimeout > time.Minute {
		return nil, fmt.Errorf("%w: controller safety bounds are invalid", ErrController)
	}
	return &Controller{
		verifier: options.Verifier, replay: options.Replay, runs: options.Runs, artifacts: options.Artifacts,
		capabilities: options.Capabilities, workers: options.Workers, clock: options.Clock, owner: options.Owner,
		maxAttempts: options.MaxAttempts, leaseTTL: options.LeaseTTL, cancelGrace: options.CancelGrace,
		forceTimeout: options.ForceTimeout, releaseTimeout: options.ReleaseTimeout, revokeTimeout: options.RevokeTimeout,
		retryDelay: options.RetryDelay,
	}, nil
}

func (controller *Controller) Run(ctx context.Context, request RunRequest) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if request.Events == nil {
		request.Events = func(buildworker.Event) {}
	}
	verified, err := controller.verifier.Verify(request.Envelope)
	if err != nil {
		return Result{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, verified.Payload.ExpiresAt)
	if err != nil {
		return Result{}, fmt.Errorf("%w: verified assignment expiry is invalid", ErrController)
	}
	reservation := buildcell.Reservation{
		CellID: verified.Payload.CellID, BuildID: verified.Payload.BuildID, Generation: verified.Payload.Generation,
		Nonce: verified.Payload.Nonce, PayloadDigest: verified.PayloadDigest, ExpiresAt: expiresAt,
	}
	reservationOutcome, err := controller.replay.Reserve(ctx, reservation)
	if err != nil {
		return Result{}, err
	}
	if reservationOutcome == buildcell.ReservationStale || reservationOutcome == buildcell.ReservationConflict {
		return Result{}, fmt.Errorf("%w: assignment replay outcome %s", ErrController, reservationOutcome)
	}
	owner, err := controller.owner()
	if err != nil || owner == "" {
		return Result{}, fmt.Errorf("%w: create run owner", ErrController)
	}
	now := controller.clock().UTC()
	claimOutcome, record, err := controller.runs.Claim(ctx, ClaimRequest{
		BuildID: verified.Payload.BuildID, Generation: verified.Payload.Generation, PayloadDigest: verified.PayloadDigest,
		Owner: owner, Now: now, LeaseTTL: controller.leaseTTL,
	})
	if err != nil {
		return Result{}, err
	}
	resumed := claimOutcome == ClaimResumed
	switch claimOutcome {
	case ClaimReplay:
		if !record.Result.Terminal() {
			return Result{}, fmt.Errorf("%w: replay record is not terminal", ErrController)
		}
		result := record.Result
		result.Replay = true
		return result, nil
	case ClaimInProgress:
		return Result{}, ErrInProgress
	case ClaimConflict:
		return Result{}, fmt.Errorf("%w: run claim conflicts with immutable assignment", ErrController)
	case ClaimAccepted, ClaimResumed:
	default:
		return Result{}, fmt.Errorf("%w: unknown run claim outcome", ErrController)
	}

	emit := newEventEmitter(request.Events, controller.clock)
	startedAt := record.Result.StartedAt
	if startedAt.IsZero() {
		startedAt = now
	}
	emit.phase(buildworker.PhaseAccepted, record.Attempt, "Assignment signature, audience, generation, expiry, and replay identity verified.")
	if resumed {
		emit.phase(buildworker.PhaseCleaning, record.Attempt, "Scrubbing stale worker resources before resuming the durable run.")
		cleanupContext, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), controller.releaseTimeout)
		cleanup, cleanupErr := controller.workers.CleanupBuild(cleanupContext, verified.Payload.BuildID)
		cleanupCancel()
		cleanup = combineCleanupReports(verified.Payload.BuildID, cleanup)
		if cleanupErr != nil || !cleanupProvenClean(cleanup) {
			result := Result{
				BuildID: verified.Payload.BuildID, PayloadDigest: verified.PayloadDigest, Phase: buildworker.PhaseQuarantined,
				Attempts: record.Attempt, Cleanup: cleanup, ErrorCode: "cleanup_quarantined", StartedAt: startedAt, FinishedAt: controller.clock().UTC(),
			}
			emit.phase(buildworker.PhaseQuarantined, record.Attempt, "Stale worker cleanup could not be proven; the build remains quarantined.")
			return controller.finishResult(context.WithoutCancel(ctx), owner, result, emit)
		}
	}
	if record.CancelRequested {
		emit.phase(buildworker.PhaseCanceled, record.Attempt, "Persisted cancellation prevented build execution.")
		result := canceledWithoutWorkerResult(verified, startedAt, controller.clock().UTC(), record.Attempt)
		return controller.finishResult(context.WithoutCancel(ctx), owner, result, emit)
	}
	runContext, cancelRun := contextWithCancellation(ctx, request.Cancellation)
	defer cancelRun()
	if err := controller.update(ctx, verified.Payload.BuildID, owner, buildworker.PhaseResolving, record.Attempt); err != nil {
		return Result{}, err
	}
	emit.phase(buildworker.PhaseResolving, record.Attempt, "Resolving signed immutable build artifacts.")
	resolved, err := buildcell.Resolve(runContext, verified, controller.artifacts)
	if err != nil {
		if runContext.Err() != nil {
			emit.phase(buildworker.PhaseCanceled, record.Attempt, "Cancellation stopped assignment artifact resolution.")
			result := canceledWithoutWorkerResult(verified, startedAt, controller.clock().UTC(), record.Attempt)
			return controller.finishResult(context.WithoutCancel(ctx), owner, result, emit)
		}
		result := failedResult(verified, startedAt, controller.clock().UTC(), record.Attempt, "assignment_resolution")
		emit.phase(buildworker.PhaseFailed, record.Attempt, "Assignment artifact resolution failed.")
		result, finishErr := controller.finishResult(ctx, owner, result, emit)
		if finishErr != nil {
			return Result{}, finishErr
		}
		return result, nil
	}

	firstAttempt := record.Attempt + 1
	if firstAttempt == 0 {
		firstAttempt = 1
	}
	for attempt := firstAttempt; attempt <= controller.maxAttempts; attempt++ {
		result, retry, runErr := controller.runAttempt(runContext, request.Cancellation, resolved, owner, attempt, startedAt, expiresAt, emit)
		if runErr != nil {
			return Result{}, runErr
		}
		if !retry {
			result, err = controller.finishResult(ctx, owner, result, emit)
			if err != nil {
				return Result{}, err
			}
			return result, nil
		}
		delay := controller.retryDelay(attempt)
		if delay < 0 || delay > time.Minute {
			return Result{}, fmt.Errorf("%w: retry delay is outside bounds", ErrController)
		}
		emit.phase(buildworker.PhaseRetrying, attempt, "Disposable worker was lost; retrying from the immutable assignment.")
		if err := controller.update(ctx, verified.Payload.BuildID, owner, buildworker.PhaseRetrying, attempt); err != nil {
			return Result{}, err
		}
		if err := waitForRetry(runContext, request.Cancellation, delay); err != nil {
			emit.phase(buildworker.PhaseCanceled, attempt, "Cancellation stopped the worker retry delay.")
			canceled := canceledResult(verified, startedAt, controller.clock().UTC(), attempt, result.Worker)
			canceled, finishErr := controller.finishResult(context.WithoutCancel(ctx), owner, canceled, emit)
			if finishErr != nil {
				return Result{}, finishErr
			}
			return canceled, nil
		}
	}
	result := failedResult(verified, startedAt, controller.clock().UTC(), controller.maxAttempts, "worker_lost")
	result, err = controller.finishResult(ctx, owner, result, emit)
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (controller *Controller) runAttempt(ctx context.Context, cancellation <-chan struct{}, assignment buildcell.ResolvedAssignment, owner string, attempt uint32, startedAt, expiresAt time.Time, emit *eventEmitter) (Result, bool, error) {
	buildID := assignment.Verified.Payload.BuildID
	if ctx.Err() != nil || cancellationRequested(cancellation) {
		return canceledWithoutWorkerResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt-1), false, nil
	}
	if err := controller.update(ctx, buildID, owner, buildworker.PhaseAllocating, attempt); err != nil {
		return Result{}, false, err
	}
	emit.phase(buildworker.PhaseAllocating, attempt, "Acquiring short-lived capabilities and a disposable worker.")
	lease, err := controller.capabilities.Acquire(ctx, assignment.Verified, attempt)
	defer wipeLeaseSecrets(lease.Secrets)
	if err != nil {
		if lease.ID != "" && controller.revokeLease(ctx, lease) != nil {
			return capabilityRevokeResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		if ctx.Err() != nil || cancellationRequested(cancellation) {
			return canceledWithoutWorkerResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		return failedResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt, "capability_acquire"), false, nil
	}
	if err := validateCapabilityLease(lease, assignment.Verified, controller.clock().UTC(), expiresAt); err != nil {
		if controller.revokeLease(ctx, lease) != nil {
			return capabilityRevokeResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		return failedResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt, "capability_invalid"), false, nil
	}
	remaining := expiresAt.Sub(controller.clock().UTC())
	if remaining <= 0 {
		if controller.revokeLease(ctx, lease) != nil {
			return capabilityRevokeResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		return failedResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt, "assignment_expired"), false, nil
	}
	worker, err := controller.workers.Allocate(ctx, AllocationRequest{
		Assignment: assignment, Attempt: attempt, LeaseID: lease.ID, ExpiresAt: lease.ExpiresAt,
		Network: append([]llbcompiler.NetworkCapability(nil), lease.Network...), Caches: append([]llbcompiler.CacheCapability(nil), lease.Caches...),
	})
	if err != nil {
		if controller.revokeLease(ctx, lease) != nil {
			return capabilityRevokeResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		if ctx.Err() != nil || cancellationRequested(cancellation) {
			return canceledWithoutWorkerResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt), false, nil
		}
		return failedResult(assignment.Verified, startedAt, controller.clock().UTC(), attempt, "worker_allocate"), false, nil
	}

	attemptContext, cancelAttempt := context.WithTimeout(ctx, remaining)
	defer cancelAttempt()
	done := make(chan attemptExecution, 1)
	go func() {
		result, executeErr := worker.Execute(attemptContext, buildworker.Request{
			Assignment: assignment, Attempt: attempt, Secrets: lease.Secrets, Events: emit.worker,
		})
		done <- attemptExecution{result: result, err: executeErr}
	}()

	heartbeat := time.NewTicker(controller.leaseTTL / 3)
	defer heartbeat.Stop()
	var executed attemptExecution
	var forcedReport buildworker.CleanupReport
	forced := false
	canceled := false
	controlLost := false
executionLoop:
	for {
		select {
		case executed = <-done:
			break executionLoop
		case <-cancellation:
			canceled = true
			cancelAttempt()
			if err := controller.update(context.WithoutCancel(ctx), buildID, owner, buildworker.PhaseCanceling, attempt); err != nil {
				controlLost = true
			}
			emit.phase(buildworker.PhaseCanceling, attempt, "Cancellation requested; waiting for cooperative worker shutdown.")
			executed, forcedReport, forced = controller.awaitOrForce(worker, done)
			break executionLoop
		case <-ctx.Done():
			canceled = true
			cancelAttempt()
			emit.phase(buildworker.PhaseCanceling, attempt, "Controller context canceled; stopping the worker.")
			executed, forcedReport, forced = controller.awaitOrForce(worker, done)
			break executionLoop
		case <-heartbeat.C:
			if err := controller.update(context.Background(), buildID, owner, buildworker.PhaseSolving, attempt); err != nil {
				controlLost = true
				cancelAttempt()
				executed, forcedReport, forced = controller.awaitOrForce(worker, done)
				break executionLoop
			}
		}
	}

	releaseContext, releaseCancel := context.WithTimeout(context.Background(), controller.releaseTimeout)
	releaseReport, releaseErr := worker.Release(releaseContext)
	releaseCancel()
	revokeErr := controller.revokeLease(ctx, lease)
	cleanup := combineCleanupReports(buildID, executed.result.Cleanup, releaseReport)
	if releaseErr != nil {
		cleanup.Status = buildworker.CleanupQuarantined
		cleanup.Residue = append(cleanup.Residue, buildworker.Residue{Kind: "worker_resource", Detail: "worker release failed"})
		cleanup.QuarantineReason = appendReason(cleanup.QuarantineReason, "worker release failed")
	}
	if revokeErr != nil {
		cleanup.Status = buildworker.CleanupQuarantined
		cleanup.Residue = append(cleanup.Residue, buildworker.Residue{Kind: "temporary_credential", Detail: "capability revocation failed"})
		cleanup.QuarantineReason = appendReason(cleanup.QuarantineReason, "capability revocation failed")
	}
	cleanupClean := cleanupProvenClean(cleanup)
	if forced {
		cleanup = combineCleanupReports(buildID, cleanup, forcedReport)
		cleanupClean = cleanupProvenClean(cleanup)
	}
	result := Result{
		BuildID: buildID, PayloadDigest: assignment.Verified.PayloadDigest, Attempts: attempt,
		WorkerIdentity: worker.Identity(), Worker: executed.result, Cleanup: cleanup, StartedAt: startedAt, FinishedAt: controller.clock().UTC(),
	}
	if !cleanupClean {
		result.Phase = buildworker.PhaseQuarantined
		result.ErrorCode = "cleanup_quarantined"
		emit.phase(result.Phase, attempt, "Worker cleanup could not be proven; the worker is quarantined.")
		return result, false, nil
	}
	if controlLost {
		return Result{}, false, fmt.Errorf("%w: durable run lease was lost", ErrController)
	}
	if canceled {
		result.Phase = buildworker.PhaseCanceled
		result.ErrorCode = "canceled"
		emit.phase(result.Phase, attempt, "Build canceled and cleanup verified.")
		return result, false, nil
	}
	if executed.result.ErrorCode == "worker_lost" && attempt < controller.maxAttempts {
		result.Phase = buildworker.PhaseRetrying
		result.ErrorCode = "worker_lost"
		return result, true, nil
	}
	if executed.err != nil || executed.result.Phase != buildworker.PhaseComplete {
		result.Phase = buildworker.PhaseFailed
		result.ErrorCode = executed.result.ErrorCode
		if result.ErrorCode == "" {
			result.ErrorCode = "worker_failed"
		}
		emit.phase(result.Phase, attempt, "Build worker failed and cleanup verified.")
		return result, false, nil
	}
	if err := validateSuccessfulResult(assignment, executed.result); err != nil {
		result.Phase = buildworker.PhaseFailed
		result.ErrorCode = "result_invalid"
		emit.phase(result.Phase, attempt, "Build result did not prove all required immutable outputs.")
		return result, false, nil
	}
	result.Phase = buildworker.PhaseComplete
	emit.phase(result.Phase, attempt, "Required immutable outputs are committed and worker cleanup is verified.")
	return result, false, nil
}

func (controller *Controller) awaitOrForce(worker Worker, done <-chan attemptExecution) (attemptExecution, buildworker.CleanupReport, bool) {
	select {
	case result := <-done:
		return result, buildworker.CleanupReport{BuildID: result.result.BuildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}, false
	case <-time.After(controller.cancelGrace):
	}
	forceContext, cancel := context.WithTimeout(context.Background(), controller.forceTimeout)
	defer cancel()
	report, err := worker.ForceTerminate(forceContext)
	if err != nil {
		report.Status = buildworker.CleanupQuarantined
		report.QuarantineReason = "forced worker termination failed"
	}
	select {
	case result := <-done:
		return result, report, true
	case <-forceContext.Done():
		return attemptExecution{result: buildworker.Result{Phase: buildworker.PhaseCanceled, ErrorCode: "forced_cancel", Cleanup: report}, err: forceContext.Err()}, report, true
	}
}

func (controller *Controller) update(ctx context.Context, buildID, owner string, phase buildworker.Phase, attempt uint32) error {
	updateContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), controller.leaseTTL/2)
	defer cancel()
	return controller.runs.Heartbeat(updateContext, buildID, owner, phase, attempt, controller.clock().UTC(), controller.leaseTTL)
}

func (controller *Controller) finish(ctx context.Context, owner string, result Result) error {
	finishContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), controller.leaseTTL/2)
	defer cancel()
	return controller.runs.Finish(finishContext, result.BuildID, owner, result, controller.clock().UTC())
}

func (controller *Controller) finishResult(ctx context.Context, owner string, result Result, emit *eventEmitter) (Result, error) {
	digest, err := emit.digest()
	if err != nil {
		return Result{}, fmt.Errorf("%w: digest structured build events", ErrController)
	}
	result.LogsDigest = digest
	if err := controller.finish(ctx, owner, result); err != nil {
		return Result{}, err
	}
	return result, nil
}

func (controller *Controller) revokeLease(ctx context.Context, lease CapabilityLease) error {
	revokeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), controller.revokeTimeout)
	defer cancel()
	return controller.capabilities.Revoke(revokeContext, lease)
}

func validateCapabilityLease(lease CapabilityLease, assignment buildcell.VerifiedAssignment, now, assignmentExpiry time.Time) error {
	if lease.ID == "" || lease.ExpiresAt.IsZero() || !lease.ExpiresAt.After(now) || lease.ExpiresAt.After(assignmentExpiry) ||
		!equalNetworkCapabilities(lease.Network, assignment.Payload.Lock.Network) || !slices.Equal(lease.Caches, assignment.Payload.Lock.Caches) {
		return fmt.Errorf("%w: capability lease identity or scope is invalid", ErrController)
	}
	allowed := make(map[string]bool, len(assignment.Payload.Lock.Secrets))
	for _, capability := range assignment.Payload.Lock.Secrets {
		allowed[capability.MountID] = capability.Required
	}
	for key, value := range lease.Secrets {
		if _, exists := allowed[key]; !exists || len(value) == 0 {
			return fmt.Errorf("%w: capability lease contains unknown or empty secret", ErrController)
		}
	}
	for key, required := range allowed {
		if _, exists := lease.Secrets[key]; required && !exists {
			return fmt.Errorf("%w: capability lease lacks required secret", ErrController)
		}
	}
	return nil
}

func equalNetworkCapabilities(left, right []llbcompiler.NetworkCapability) bool {
	return slices.EqualFunc(left, right, func(left, right llbcompiler.NetworkCapability) bool {
		return left.NodeID == right.NodeID && left.Profile == right.Profile && left.GatewayID == right.GatewayID && slices.Equal(left.Hosts, right.Hosts)
	})
}

func validateSuccessfulResult(assignment buildcell.ResolvedAssignment, result buildworker.Result) error {
	if result.BuildID != assignment.Verified.Payload.BuildID || result.Attempt == 0 || result.Cleanup.Status != buildworker.CleanupClean ||
		result.Cleanup.BuildID != result.BuildID || !runDigestPattern.MatchString(result.LogsDigest) || len(result.Outputs) != len(assignment.Outputs) {
		return errors.New("worker result identity is incomplete")
	}
	for index, output := range result.Outputs {
		expected := assignment.Outputs[index]
		expectedConfig := assignment.Verified.Payload.Outputs[index].ConfigDigest
		if output.Name != expected.Name || output.Kind != expected.Kind || output.ArtifactRef == "" ||
			!runDigestPattern.MatchString(output.ArtifactDigest) || output.ArtifactSize <= 0 || output.ConfigDigest != expectedConfig {
			return errors.New("worker output identity is incomplete")
		}
		if !validOutputContentIdentity(output) || !validSupplyChainIdentity(output, assignment.Verified.Payload.Lock.PolicyDigest, assignment.Verified.Payload.Lock.SupplyChain) {
			return errors.New("worker output manifest or layer identity is invalid")
		}
	}
	return nil
}

func validSupplyChainIdentity(output buildworker.OutputResult, policyDigest string, policy llbcompiler.SupplyChainPolicy) bool {
	evidence := output.SupplyChain
	if !validStoredSupplyChainIdentity(output) || evidence.PolicyDigest != policyDigest ||
		evidence.SignerKeyID != policy.SignerKeyID || evidence.SignerKeyVersion < 1 ||
		!slices.Contains(policy.AllowedSignerPublicKeyDigests, evidence.SignerPublicKeyDigest) {
		return false
	}
	return true
}

func validStoredSupplyChainIdentity(output buildworker.OutputResult) bool {
	evidence := output.SupplyChain
	if evidence.PolicyState != "accepted" || evidence.ScanState != "passed" || !runDigestPattern.MatchString(evidence.PolicyDigest) ||
		evidence.SignerKeyID == "" || evidence.SignerKeyVersion < 1 || !runDigestPattern.MatchString(evidence.SignerPublicKeyDigest) {
		return false
	}
	repository, _, found := strings.Cut(output.ArtifactRef, "@")
	if !found || repository == "" {
		return false
	}
	expectedKinds := map[string]struct{}{
		buildsupply.KindSBOM: {}, buildsupply.KindScan: {}, buildsupply.KindProvenance: {}, buildsupply.KindSignature: {}, buildsupply.KindPolicy: {},
	}
	manifestDigests := make(map[string]struct{}, len(evidence.Evidence))
	for _, reference := range evidence.Evidence {
		if _, expected := expectedKinds[reference.Kind]; !expected || reference.Reference != repository+"@"+reference.ManifestDigest ||
			!runDigestPattern.MatchString(reference.ManifestDigest) || !runDigestPattern.MatchString(reference.PayloadDigest) {
			return false
		}
		if _, duplicate := manifestDigests[reference.ManifestDigest]; duplicate {
			return false
		}
		manifestDigests[reference.ManifestDigest] = struct{}{}
		delete(expectedKinds, reference.Kind)
	}
	return len(expectedKinds) == 0
}

func validOutputContentIdentity(output buildworker.OutputResult) bool {
	if output.Kind == "static_bundle" {
		return runDigestPattern.MatchString(output.ManifestDigest) && strings.HasPrefix(output.PublicationManifestRef, "s3://") && len(output.LayerDigests) == 0
	}
	if output.Kind != "oci_image" || output.PublicationManifestRef != "" || !runDigestPattern.MatchString(output.ManifestDigest) || len(output.LayerDigests) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(output.LayerDigests))
	for _, layer := range output.LayerDigests {
		if !runDigestPattern.MatchString(layer) {
			return false
		}
		if _, duplicate := seen[layer]; duplicate {
			return false
		}
		seen[layer] = struct{}{}
	}
	return true
}

func cleanupProvenClean(report buildworker.CleanupReport) bool {
	return report.Status == buildworker.CleanupClean && len(report.Residue) == 0 && report.QuarantineReason == ""
}

func combineCleanupReports(buildID string, reports ...buildworker.CleanupReport) buildworker.CleanupReport {
	combined := buildworker.CleanupReport{BuildID: buildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}
	for _, report := range reports {
		if report.BuildID != "" && report.BuildID != buildID {
			combined.Status = buildworker.CleanupQuarantined
			combined.Residue = append(combined.Residue, buildworker.Residue{Kind: "cleanup_identity", Detail: "cleanup report belongs to another build"})
			combined.QuarantineReason = appendReason(combined.QuarantineReason, "cleanup identity mismatch")
		}
		combined.Residue = append(combined.Residue, report.Residue...)
		combined.RemovedPaths = append(combined.RemovedPaths, report.RemovedPaths...)
		if !cleanupProvenClean(report) {
			combined.Status = buildworker.CleanupQuarantined
			combined.QuarantineReason = appendReason(combined.QuarantineReason, report.QuarantineReason)
		}
	}
	if len(combined.Residue) > 0 {
		combined.Status = buildworker.CleanupQuarantined
		combined.QuarantineReason = appendReason(combined.QuarantineReason, "residue remains")
	}
	return combined
}

func appendReason(existing, reason string) string {
	if reason == "" {
		return existing
	}
	if existing == "" {
		return reason
	}
	return existing + "; " + reason
}

func failedResult(assignment buildcell.VerifiedAssignment, startedAt, finishedAt time.Time, attempts uint32, code string) Result {
	return Result{BuildID: assignment.Payload.BuildID, PayloadDigest: assignment.PayloadDigest, Phase: buildworker.PhaseFailed, Attempts: attempts, ErrorCode: code, StartedAt: startedAt, FinishedAt: finishedAt, Cleanup: noResourceCleanup(assignment.Payload.BuildID)}
}

func capabilityRevokeResult(assignment buildcell.VerifiedAssignment, startedAt, finishedAt time.Time, attempts uint32) Result {
	result := failedResult(assignment, startedAt, finishedAt, attempts, "capability_revoke")
	result.Phase = buildworker.PhaseQuarantined
	result.Cleanup = buildworker.CleanupReport{
		BuildID: assignment.Payload.BuildID, Status: buildworker.CleanupQuarantined,
		Residue:      []buildworker.Residue{{Kind: "temporary_credential", Detail: "capability revocation failed"}},
		RemovedPaths: []string{}, QuarantineReason: "capability revocation failed",
	}
	return result
}

func canceledResult(assignment buildcell.VerifiedAssignment, startedAt, finishedAt time.Time, attempts uint32, worker buildworker.Result) Result {
	return Result{BuildID: assignment.Payload.BuildID, PayloadDigest: assignment.PayloadDigest, Phase: buildworker.PhaseCanceled, Attempts: attempts, Worker: worker, Cleanup: worker.Cleanup, ErrorCode: "canceled", StartedAt: startedAt, FinishedAt: finishedAt}
}

func canceledWithoutWorkerResult(assignment buildcell.VerifiedAssignment, startedAt, finishedAt time.Time, attempts uint32) Result {
	return Result{
		BuildID: assignment.Payload.BuildID, PayloadDigest: assignment.PayloadDigest, Phase: buildworker.PhaseCanceled,
		Attempts: attempts, Cleanup: noResourceCleanup(assignment.Payload.BuildID), ErrorCode: "canceled", StartedAt: startedAt, FinishedAt: finishedAt,
	}
}

func noResourceCleanup(buildID string) buildworker.CleanupReport {
	return buildworker.CleanupReport{BuildID: buildID, Status: buildworker.CleanupClean, Residue: []buildworker.Residue{}, RemovedPaths: []string{}}
}

func waitForRetry(ctx context.Context, cancellation <-chan struct{}, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-cancellation:
		return context.Canceled
	}
}

func contextWithCancellation(parent context.Context, cancellation <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if cancellation != nil {
		go func() {
			select {
			case <-cancellation:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}

func cancellationRequested(cancellation <-chan struct{}) bool {
	select {
	case <-cancellation:
		return true
	default:
		return false
	}
}

func wipeLeaseSecrets(values map[string][]byte) {
	for key, value := range values {
		for index := range value {
			value[index] = 0
		}
		delete(values, key)
	}
}

func randomOwner() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "run-" + hex.EncodeToString(value[:]), nil
}

type eventEmitter struct {
	mu         sync.Mutex
	sequence   uint64
	sink       EventSink
	clock      func() time.Time
	transcript hash.Hash
	digestErr  error
}

func newEventEmitter(sink EventSink, clock func() time.Time) *eventEmitter {
	return &eventEmitter{sink: sink, clock: clock, transcript: sha256.New()}
}

func (emitter *eventEmitter) worker(event buildworker.Event) {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	emitter.sequence++
	event.Sequence = emitter.sequence
	if event.OccurredAt.IsZero() {
		event.OccurredAt = emitter.clock().UTC()
	}
	encoded, err := canonicaljson.Marshal(event)
	if err != nil {
		emitter.digestErr = err
	} else {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
		_, _ = emitter.transcript.Write(length[:])
		_, _ = emitter.transcript.Write(encoded)
	}
	emitter.sink(event)
}

func (emitter *eventEmitter) phase(phase buildworker.Phase, attempt uint32, message string) {
	emitter.worker(buildworker.Event{Attempt: attempt, Phase: phase, Kind: "phase", Message: message, OccurredAt: emitter.clock().UTC()})
}

func (emitter *eventEmitter) digest() (string, error) {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if emitter.digestErr != nil {
		return "", emitter.digestErr
	}
	return "sha256:" + hex.EncodeToString(emitter.transcript.Sum(nil)), nil
}
