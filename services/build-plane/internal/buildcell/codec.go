package buildcell

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/mayowaoladosu/layerrail-lrail/internal/canonicaljson"
)

const MaxEnvelopeBytes = 1 << 20

func DecodeEnvelope(contents []byte) (Envelope, error) {
	if len(contents) == 0 || len(contents) > MaxEnvelopeBytes {
		return Envelope{}, assignmentError("assignment.envelope_size", "Assignment envelope is empty or oversized.")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, assignmentError("assignment.envelope_json", "Assignment envelope is malformed.")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Envelope{}, assignmentError("assignment.envelope_json", "Assignment envelope has trailing data.")
	}
	canonical, err := canonicaljson.Marshal(envelope)
	if err != nil || !bytes.Equal(contents, canonical) {
		return Envelope{}, assignmentError("assignment.envelope_canonical", "Assignment envelope is not canonical JSON.")
	}
	return envelope, nil
}

func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	contents, err := canonicaljson.Marshal(envelope)
	if err != nil || len(contents) > MaxEnvelopeBytes {
		return nil, assignmentError("assignment.envelope_canonical", "Assignment envelope cannot be encoded within limits.")
	}
	return contents, nil
}
