// Package meter verifies signed usage facts and maintains idempotent per-source
// sequence watermarks without treating transport delivery as financial truth.
package meter

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
	"github.com/mayowaoladosu/layerrail-lrail/internal/platformid"
)

const (
	MaxBatchFacts = 1000
	MaxFactWindow = 24 * time.Hour
	FutureSkew    = 5 * time.Minute
)

var ErrInvalid = errors.New("invalid usage fact")

type Fact struct {
	FactID         string            `json:"fact_id"`
	OrganizationID string            `json:"organization_id"`
	ResourceID     string            `json:"resource_id"`
	SourceID       string            `json:"source_id"`
	SourceEpoch    string            `json:"source_epoch"`
	Sequence       uint64            `json:"sequence"`
	MeterType      string            `json:"meter_type"`
	Quantity       int64             `json:"quantity"`
	Unit           string            `json:"unit"`
	StartTime      time.Time         `json:"start_time"`
	EndTime        time.Time         `json:"end_time"`
	CorrelationID  string            `json:"correlation_id"`
	CorrectionOf   string            `json:"correction_of,omitempty"`
	Attributes     map[string]string `json:"attributes"`
	KeyID          string            `json:"key_id"`
	Signature      string            `json:"signature,omitempty"`
}

type VerifiedFact struct {
	Fact   Fact
	Digest string
}

type BatchResult struct {
	Accepted         int
	Duplicates       int
	MissingSequences map[string][]uint64
	Watermarks       map[string]uint64
}

type Journal interface {
	AppendBatch(ctx context.Context, facts []VerifiedFact) (BatchResult, error)
}

type Ingestor struct {
	SourceKeys map[string]map[string]ed25519.PublicKey
	Journal    Journal
	Now        func() time.Time
}

func Sign(fact *Fact, keyID string, privateKey ed25519.PrivateKey) error {
	if fact == nil || keyID == "" || len(privateKey) != ed25519.PrivateKeySize {
		return invalidf("signing input is incomplete")
	}
	fact.KeyID = keyID
	fact.Signature = ""
	payload, err := signingBytes(*fact)
	if err != nil {
		return err
	}
	fact.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

func (ingestor Ingestor) Ingest(ctx context.Context, facts []Fact) (BatchResult, error) {
	if ctx == nil || ingestor.Journal == nil || ingestor.Now == nil {
		return BatchResult{}, invalidf("ingestor dependencies are incomplete")
	}
	if len(facts) == 0 || len(facts) > MaxBatchFacts {
		return BatchResult{}, invalidf("batch size is outside policy")
	}
	verified := make([]VerifiedFact, 0, len(facts))
	for _, fact := range facts {
		digest, err := ingestor.verify(fact)
		if err != nil {
			return BatchResult{}, err
		}
		verified = append(verified, VerifiedFact{Fact: fact, Digest: digest})
	}
	return ingestor.Journal.AppendBatch(ctx, verified)
}

func (ingestor Ingestor) verify(fact Fact) (string, error) {
	factID, err := platformid.Parse(fact.FactID)
	if err != nil || factID.Prefix() != "use" {
		return "", invalidf("fact ID is invalid")
	}
	organizationID, err := platformid.Parse(fact.OrganizationID)
	if err != nil || organizationID.Prefix() != "org" {
		return "", invalidf("organization ID is invalid")
	}
	if _, err := platformid.Parse(fact.ResourceID); err != nil {
		return "", invalidf("resource ID is invalid")
	}
	if fact.SourceID == "" || fact.SourceEpoch == "" || fact.Sequence == 0 || fact.CorrelationID == "" {
		return "", invalidf("source, sequence, and correlation are required")
	}
	allowedUnits := map[string]string{
		"compute_cpu_seconds":          "cpu_second",
		"compute_memory_bytes_seconds": "byte_second",
		"storage_bytes_seconds":        "byte_second",
		"network_egress_bytes":         "byte",
		"build_seconds":                "second",
		"cdn_requests":                 "request",
		"cdn_bytes":                    "byte",
	}
	unit, ok := allowedUnits[fact.MeterType]
	if !ok || fact.Unit != unit {
		return "", invalidf("meter type or unit is invalid")
	}
	if fact.Quantity == 0 || (fact.Quantity < 0 && fact.CorrectionOf == "") {
		return "", invalidf("quantity requires a positive measurement or named correction")
	}
	if !fact.EndTime.After(fact.StartTime) || fact.EndTime.Sub(fact.StartTime) > MaxFactWindow || fact.EndTime.After(ingestor.Now().UTC().Add(FutureSkew)) {
		return "", invalidf("fact time window is outside policy")
	}
	keys, ok := ingestor.SourceKeys[fact.SourceID]
	if !ok {
		return "", invalidf("source is not trusted")
	}
	key, ok := keys[fact.KeyID]
	if !ok || len(key) != ed25519.PublicKeySize {
		return "", invalidf("source key is not trusted")
	}
	signature, err := base64.StdEncoding.DecodeString(fact.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", invalidf("signature encoding is invalid")
	}
	payload, err := signingBytes(fact)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(key, payload, signature) {
		return "", invalidf("signature verification failed")
	}
	full, err := canonicaljson.Marshal(fact)
	if err != nil {
		return "", invalidf("fact canonicalization failed: %v", err)
	}
	digest := sha256.Sum256(full)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func signingBytes(fact Fact) ([]byte, error) {
	fact.Signature = ""
	payload, err := canonicaljson.Marshal(fact)
	if err != nil {
		return nil, invalidf("signing payload canonicalization failed: %v", err)
	}
	return payload, nil
}

type MemoryJournal struct {
	mu      sync.Mutex
	sources map[string]*sourceState
}

type sourceState struct {
	watermark uint64
	records   map[uint64]string
}

func NewMemoryJournal() *MemoryJournal {
	return &MemoryJournal{sources: make(map[string]*sourceState)}
}

func (journal *MemoryJournal) AppendBatch(ctx context.Context, facts []VerifiedFact) (BatchResult, error) {
	if err := ctx.Err(); err != nil {
		return BatchResult{}, err
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()

	batchSequences := make(map[string]map[uint64]string)
	for _, fact := range facts {
		key := sourceKey(fact.Fact)
		if batchSequences[key] == nil {
			batchSequences[key] = make(map[uint64]string)
		}
		if existing, ok := batchSequences[key][fact.Fact.Sequence]; ok && existing != fact.Digest {
			return BatchResult{}, invalidf("sequence %d is inconsistent within the batch", fact.Fact.Sequence)
		}
		batchSequences[key][fact.Fact.Sequence] = fact.Digest
		state := journal.sources[key]
		if state == nil {
			continue
		}
		if existing, ok := state.records[fact.Fact.Sequence]; ok && existing != fact.Digest {
			return BatchResult{}, invalidf("sequence %d was reused with different content", fact.Fact.Sequence)
		}
	}

	result := BatchResult{MissingSequences: make(map[string][]uint64), Watermarks: make(map[string]uint64)}
	for _, fact := range facts {
		key := sourceKey(fact.Fact)
		state := journal.sources[key]
		if state == nil {
			state = &sourceState{records: make(map[uint64]string)}
			journal.sources[key] = state
		}
		if _, duplicate := state.records[fact.Fact.Sequence]; duplicate {
			result.Duplicates++
			continue
		}
		state.records[fact.Fact.Sequence] = fact.Digest
		result.Accepted++
	}
	for key, state := range journal.sources {
		for {
			if _, exists := state.records[state.watermark+1]; !exists {
				break
			}
			state.watermark++
		}
		result.Watermarks[key] = state.watermark
		sequences := make([]uint64, 0, len(state.records))
		for sequence := range state.records {
			sequences = append(sequences, sequence)
		}
		slices.Sort(sequences)
		if len(sequences) > 0 {
			maximum := sequences[len(sequences)-1]
			for missing := state.watermark + 1; missing < maximum && len(result.MissingSequences[key]) < 1000; missing++ {
				if _, exists := state.records[missing]; !exists {
					result.MissingSequences[key] = append(result.MissingSequences[key], missing)
				}
			}
		}
	}
	return result, nil
}

func sourceKey(fact Fact) string {
	return fact.SourceID + "/" + fact.SourceEpoch
}

func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}
