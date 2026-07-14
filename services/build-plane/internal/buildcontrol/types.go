// Package buildcontrol orchestrates verified assignments across disposable workers.
package buildcontrol

import (
	"context"
	"errors"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildcell"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/buildworker"
	"github.com/mayowaoladosu/layerrail-lrail/services/build-plane/internal/llbcompiler"
)

var (
	ErrController = errors.New("build cell controller failed")
	ErrInProgress = errors.New("build assignment is already in progress")
)

const (
	AllocationCertificateIssue = "worker_certificate_issue"
	AllocationResourcePrepare  = "worker_resource_prepare"
	AllocationStaleCleanup     = "worker_stale_cleanup"
	AllocationResourceCreate   = "worker_resource_create"
	AllocationReadiness        = "worker_readiness"
	AllocationConnect          = "worker_connect"
	AllocationConnectDial      = "worker_connect_dial"
	AllocationConnectTLS       = "worker_connect_tls"
	AllocationConnectVerify    = "worker_connect_verify"
)

type WorkerAllocationError struct {
	Code string
	Err  error
}

func (failure *WorkerAllocationError) Error() string {
	return "worker allocation failed at " + failure.Code
}
func (failure *WorkerAllocationError) Unwrap() error { return failure.Err }

func WrapWorkerAllocationError(code string, err error) error {
	if err == nil || !validWorkerAllocationCode(code) {
		return errors.New("worker allocation failure classification is invalid")
	}
	return &WorkerAllocationError{Code: code, Err: err}
}

func WorkerAllocationErrorCode(err error) string {
	var failure *WorkerAllocationError
	if errors.As(err, &failure) && validWorkerAllocationCode(failure.Code) {
		return failure.Code
	}
	return "worker_allocate"
}

func validWorkerAllocationCode(code string) bool {
	switch code {
	case AllocationCertificateIssue, AllocationResourcePrepare, AllocationStaleCleanup,
		AllocationResourceCreate, AllocationReadiness, AllocationConnect, AllocationConnectDial,
		AllocationConnectTLS, AllocationConnectVerify:
		return true
	default:
		return false
	}
}

type Result struct {
	BuildID        string                    `json:"build_id"`
	PayloadDigest  string                    `json:"payload_digest"`
	Phase          buildworker.Phase         `json:"phase"`
	Attempts       uint32                    `json:"attempts"`
	WorkerIdentity string                    `json:"worker_identity,omitempty"`
	Worker         buildworker.Result        `json:"worker"`
	Cleanup        buildworker.CleanupReport `json:"cleanup"`
	ErrorCode      string                    `json:"error_code,omitempty"`
	LogsDigest     string                    `json:"logs_digest,omitempty"`
	StartedAt      time.Time                 `json:"started_at"`
	FinishedAt     time.Time                 `json:"finished_at"`
	Replay         bool                      `json:"replay"`
}

func (result Result) Terminal() bool {
	return result.Phase == buildworker.PhaseComplete || result.Phase == buildworker.PhaseFailed ||
		result.Phase == buildworker.PhaseCanceled || result.Phase == buildworker.PhaseQuarantined
}

type CapabilityLease struct {
	ID        string
	ExpiresAt time.Time
	Secrets   map[string][]byte
	Network   []llbcompiler.NetworkCapability
	Caches    []llbcompiler.CacheCapability
}

type CapabilityBroker interface {
	Acquire(ctx context.Context, assignment buildcell.VerifiedAssignment, attempt uint32) (CapabilityLease, error)
	Revoke(ctx context.Context, lease CapabilityLease) error
}

type AllocationRequest struct {
	Assignment buildcell.ResolvedAssignment
	Attempt    uint32
	LeaseID    string
	ExpiresAt  time.Time
	Network    []llbcompiler.NetworkCapability
	Caches     []llbcompiler.CacheCapability
}

type Worker interface {
	Identity() string
	Execute(ctx context.Context, request buildworker.Request) (buildworker.Result, error)
	ForceTerminate(ctx context.Context) (buildworker.CleanupReport, error)
	Release(ctx context.Context) (buildworker.CleanupReport, error)
}

type WorkerAllocator interface {
	Allocate(ctx context.Context, request AllocationRequest) (Worker, error)
	CleanupBuild(ctx context.Context, buildID string) (buildworker.CleanupReport, error)
}

type ClaimOutcome string

const (
	ClaimAccepted   ClaimOutcome = "accepted"
	ClaimResumed    ClaimOutcome = "resumed"
	ClaimInProgress ClaimOutcome = "in_progress"
	ClaimReplay     ClaimOutcome = "replay"
	ClaimConflict   ClaimOutcome = "conflict"
)

type ClaimRequest struct {
	BuildID       string
	Generation    uint64
	PayloadDigest string
	Owner         string
	Now           time.Time
	LeaseTTL      time.Duration
}

type RunRecord struct {
	Version         int               `json:"version"`
	BuildID         string            `json:"build_id"`
	Generation      uint64            `json:"generation"`
	PayloadDigest   string            `json:"payload_digest"`
	Owner           string            `json:"owner"`
	LeaseUntil      time.Time         `json:"lease_until"`
	Phase           buildworker.Phase `json:"phase"`
	Attempt         uint32            `json:"attempt"`
	Result          Result            `json:"result"`
	UpdatedAt       time.Time         `json:"updated_at"`
	CancelRequested bool              `json:"cancel_requested"`
}

type RunStore interface {
	Claim(ctx context.Context, request ClaimRequest) (ClaimOutcome, RunRecord, error)
	Heartbeat(ctx context.Context, buildID, owner string, phase buildworker.Phase, attempt uint32, now time.Time, leaseTTL time.Duration) error
	Finish(ctx context.Context, buildID, owner string, result Result, now time.Time) error
	Lookup(ctx context.Context, buildID string) (RunRecord, bool, error)
	RequestCancel(ctx context.Context, buildID string, generation uint64, now time.Time) (bool, error)
}

type EventSink func(buildworker.Event)

type RunRequest struct {
	Envelope     buildcell.Envelope
	Cancellation <-chan struct{}
	Events       EventSink
}
