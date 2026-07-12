package meter

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func meterKeys() (ed25519.PublicKey, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	return private.Public().(ed25519.PublicKey), private
}

func fact(sequence uint64, now time.Time) Fact {
	return Fact{
		FactID: "use_019b01da-7e31-7000-8000-000000000001", OrganizationID: "org_019b01da-7e31-7000-8000-000000000002",
		ResourceID: "svc_019b01da-7e31-7000-8000-000000000003", SourceID: "cell-central-us-agent-1", SourceEpoch: "boot-1",
		Sequence: sequence, MeterType: "compute_cpu_seconds", Quantity: 30, Unit: "cpu_second",
		StartTime: now.Add(-time.Minute), EndTime: now, CorrelationID: "req_0123456789abcdef0123456789abcdef",
		Attributes: map[string]string{"region": "central-us"},
	}
}

func ingestor(now time.Time, public ed25519.PublicKey, journal Journal) Ingestor {
	return Ingestor{
		SourceKeys: map[string]map[string]ed25519.PublicKey{"cell-central-us-agent-1": {"meter-key-1": public}},
		Journal:    journal, Now: func() time.Time { return now },
	}
}

func signedFact(t *testing.T, sequence uint64, now time.Time, private ed25519.PrivateKey) Fact {
	t.Helper()
	value := fact(sequence, now)
	if err := Sign(&value, "meter-key-1", private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return value
}

func TestIngestHandlesReplayOutOfOrderAndGapClosure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC)
	public, private := meterKeys()
	journal := NewMemoryJournal()
	service := ingestor(now, public, journal)
	first := signedFact(t, 1, now, private)
	third := signedFact(t, 3, now, private)
	result, err := service.Ingest(context.Background(), []Fact{first, third, first})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	key := "cell-central-us-agent-1/boot-1"
	if result.Accepted != 2 || result.Duplicates != 1 || result.Watermarks[key] != 1 || len(result.MissingSequences[key]) != 1 || result.MissingSequences[key][0] != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	second := signedFact(t, 2, now, private)
	result, err = service.Ingest(context.Background(), []Fact{second})
	if err != nil {
		t.Fatalf("Ingest second: %v", err)
	}
	if result.Watermarks[key] != 3 || len(result.MissingSequences[key]) != 0 {
		t.Fatalf("gap did not close: %+v", result)
	}
}

func TestIngestRejectsSequenceReuseWithDifferentContent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, private := meterKeys()
	service := ingestor(now, public, NewMemoryJournal())
	first := signedFact(t, 1, now, private)
	if _, err := service.Ingest(context.Background(), []Fact{first}); err != nil {
		t.Fatalf("Ingest first: %v", err)
	}
	changed := fact(1, now)
	changed.Quantity = 31
	if err := Sign(&changed, "meter-key-1", private); err != nil {
		t.Fatalf("Sign changed: %v", err)
	}
	if _, err := service.Ingest(context.Background(), []Fact{changed}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("sequence reuse error = %v", err)
	}
}

func TestIngestRejectsConflictingSequenceInsideOneBatch(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, private := meterKeys()
	first := signedFact(t, 1, now, private)
	changed := fact(1, now)
	changed.Quantity = 31
	if err := Sign(&changed, "meter-key-1", private); err != nil {
		t.Fatalf("Sign changed: %v", err)
	}
	if _, err := ingestor(now, public, NewMemoryJournal()).Ingest(context.Background(), []Fact{first, changed}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("same-batch conflict error = %v", err)
	}
}

func TestIngestRejectsInvalidFactsAtomically(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, private := meterKeys()
	tests := map[string]func(*Fact){
		"bad id":                      func(value *Fact) { value.FactID = "fact-1" },
		"bad organization":            func(value *Fact) { value.OrganizationID = "prj_019b01da-7e31-7000-8000-000000000002" },
		"bad resource":                func(value *Fact) { value.ResourceID = "unknown" },
		"zero sequence":               func(value *Fact) { value.Sequence = 0 },
		"bad meter":                   func(value *Fact) { value.MeterType = "money" },
		"bad unit":                    func(value *Fact) { value.Unit = "dollars" },
		"zero quantity":               func(value *Fact) { value.Quantity = 0 },
		"negative without correction": func(value *Fact) { value.Quantity = -1 },
		"future":                      func(value *Fact) { value.EndTime = now.Add(FutureSkew + time.Second) },
		"unknown source":              func(value *Fact) { value.SourceID = "foreign-agent" },
		"unknown key":                 func(value *Fact) { value.KeyID = "unknown" },
		"bad signature":               func(value *Fact) { value.Signature = "invalid" },
	}
	for name, mutate := range tests {
		mutate := mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			value := signedFact(t, 1, now, private)
			mutate(&value)
			if _, err := ingestor(now, public, NewMemoryJournal()).Ingest(context.Background(), []Fact{value}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Ingest error = %v", err)
			}
		})
	}
}

func TestIngestAcceptsSignedCorrection(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, private := meterKeys()
	correction := fact(1, now)
	correction.Quantity = -10
	correction.CorrectionOf = "use_019b01da-7e31-7000-8000-000000000099"
	if err := Sign(&correction, "meter-key-1", private); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	result, err := ingestor(now, public, NewMemoryJournal()).Ingest(context.Background(), []Fact{correction})
	if err != nil || result.Accepted != 1 {
		t.Fatalf("Ingest correction = %+v, %v", result, err)
	}
}

func TestIngestRejectsInvalidBatchAndCancellation(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	public, _ := meterKeys()
	if _, err := ingestor(now, public, NewMemoryJournal()).Ingest(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty batch error = %v", err)
	}
	if _, err := (Ingestor{}).Ingest(context.Background(), []Fact{{}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("incomplete ingestor error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	journal := NewMemoryJournal()
	if _, err := journal.AppendBatch(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled journal error = %v", err)
	}
}
