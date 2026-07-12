// Package sourceupload coordinates bounded direct-upload parts and immutable finalization.
package sourceupload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sort"
	"strings"

	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/objectstore"
	"github.com/mayowaoladosu/layerrail-lrail/services/source-plane/internal/sourceauth"
)

var ErrInvalidParts = errors.New("invalid source upload parts")

type Part struct {
	Number int    `json:"number"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func ValidateParts(grant sourceauth.UploadGrant, parts []Part) ([]Part, error) {
	if len(parts) != grant.ExpectedParts {
		return nil, fmt.Errorf("%w: received %d parts, expected %d", ErrInvalidParts, len(parts), grant.ExpectedParts)
	}
	ordered := append([]Part(nil), parts...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Number < ordered[right].Number })
	var total int64
	for index, part := range ordered {
		if part.Number != index+1 || part.Size <= 0 || part.Size > sourceauth.MaxPartBytes || !validDigest(part.SHA256) {
			return nil, fmt.Errorf("%w: part %d violates bounds", ErrInvalidParts, part.Number)
		}
		if total > grant.ExpectedArchiveBytes-part.Size {
			return nil, fmt.Errorf("%w: part sizes exceed archive", ErrInvalidParts)
		}
		total += part.Size
	}
	if total != grant.ExpectedArchiveBytes {
		return nil, fmt.Errorf("%w: part sizes total %d, expected %d", ErrInvalidParts, total, grant.ExpectedArchiveBytes)
	}
	return ordered, nil
}

func PartKey(grant sourceauth.UploadGrant, number int) string {
	return fmt.Sprintf("uploads/%s/%s/part-%06d", grant.OrganizationID, grant.SessionID, number)
}

type PartsReader struct {
	ctx     context.Context
	store   objectstore.Store
	grant   sourceauth.UploadGrant
	parts   []Part
	index   int
	current io.ReadCloser
	hash    hash.Hash
	read    int64
}

func NewPartsReader(ctx context.Context, store objectstore.Store, grant sourceauth.UploadGrant, parts []Part) (*PartsReader, error) {
	ordered, err := ValidateParts(grant, parts)
	if err != nil {
		return nil, err
	}
	return &PartsReader{ctx: ctx, store: store, grant: grant, parts: ordered}, nil
}

func (reader *PartsReader) Read(buffer []byte) (int, error) {
	for {
		if reader.current == nil {
			if reader.index >= len(reader.parts) {
				return 0, io.EOF
			}
			part := reader.parts[reader.index]
			object, info, err := reader.store.Open(reader.ctx, PartKey(reader.grant, part.Number))
			if err != nil {
				return 0, fmt.Errorf("open source part %d: %w", part.Number, err)
			}
			if info.Size != part.Size {
				_ = object.Close()
				return 0, fmt.Errorf("%w: part %d object size is %d, expected %d", ErrInvalidParts, part.Number, info.Size, part.Size)
			}
			reader.current = object
			reader.hash = sha256.New()
			reader.read = 0
		}

		count, err := reader.current.Read(buffer)
		if count > 0 {
			reader.read += int64(count)
			_, _ = reader.hash.Write(buffer[:count])
			if reader.read > reader.parts[reader.index].Size {
				return count, fmt.Errorf("%w: part %d exceeded declared size", ErrInvalidParts, reader.parts[reader.index].Number)
			}
		}
		if errors.Is(err, io.EOF) {
			if finishErr := reader.finishPart(); finishErr != nil {
				return count, finishErr
			}
			if count > 0 {
				return count, nil
			}
			continue
		}
		if err != nil {
			return count, err
		}
		return count, nil
	}
}

func (reader *PartsReader) Close() error {
	if reader.current == nil {
		return nil
	}
	err := reader.current.Close()
	reader.current = nil
	return err
}

func (reader *PartsReader) finishPart() error {
	part := reader.parts[reader.index]
	closeErr := reader.current.Close()
	reader.current = nil
	if closeErr != nil {
		return closeErr
	}
	if reader.read != part.Size || "sha256:"+hex.EncodeToString(reader.hash.Sum(nil)) != part.SHA256 {
		return fmt.Errorf("%w: part %d digest or size mismatch", ErrInvalidParts, part.Number)
	}
	reader.index++
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
