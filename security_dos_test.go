package avro_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/arquivei/avro/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are regression coverage for docs/seguranca-2026-07-29/README.md
// SEC-01 (CVE-2026-46385 / GO-2026-5046) and SEC-02: a block header
// declaring a huge, attacker-controlled element count, followed by no data
// (immediate EOF), must produce a fast decode error instead of an
// unbounded CPU loop or an unbounded up-front allocation.
const dosRegressionTimeout = 3 * time.Second

// craftTruncatedBlock builds a single block header declaring count elements,
// with zero bytes of actual element data following it.
func craftTruncatedBlock(t *testing.T, count int64) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 64)
	w.WriteBlockHeader(count, 0)
	require.NoError(t, w.Flush())
	return buf.Bytes()
}

// assertFastError runs fn in a goroutine and requires it to return a
// non-nil error well within dosRegressionTimeout. A timeout is treated as a
// DoS regression, not a slow-test flake: every payload here is a handful of
// bytes and, once fixed, decoding fails in microseconds.
func assertFastError(t *testing.T, fn func() error) {
	t.Helper()

	done := make(chan error, 1)
	go func() { done <- fn() }()

	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(dosRegressionTimeout):
		t.Fatalf("decode did not return within %s — possible DoS regression (SEC-01/SEC-02)", dosRegressionTimeout)
	}
}

func TestSecurity_ArrayDecoder_TruncatedBlock_Generic(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := `{"type":"array","items":"long"}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var out any
		return dec.Decode(&out)
	})
}

func TestSecurity_ArrayDecoder_TruncatedBlock_Typed(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := `{"type":"array","items":"long"}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var out []int64
		return dec.Decode(&out)
	})
}

func TestSecurity_SliceSkipDecoder_TruncatedBlock(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := `{
	"type": "record",
	"name": "test",
	"fields" : [
		{"name": "a", "type": {"type": "array", "items": "long"}},
	    {"name": "b", "type": "string"}
	]
}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var got TestPartialRecord
		return dec.Decode(&got)
	})
}

func TestSecurity_MapSkipDecoder_TruncatedBlock(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := `{
	"type": "record",
	"name": "test",
	"fields" : [
		{"name": "a", "type": {"type": "map", "values": "long"}},
	    {"name": "b", "type": "string"}
	]
}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var got TestPartialRecord
		return dec.Decode(&got)
	})
}

func TestSecurity_MapDecoderUnmarshaler_TruncatedBlock(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := `{"type":"map", "values": "string"}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var got map[*textUnmarshallerInt]string
		return dec.Decode(&got)
	})
}

func TestSecurity_ReadArrayCB_TruncatedBlock(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := avro.MustParse(`{"type":"array","items":"long"}`)

	assertFastError(t, func() error {
		r := avro.NewReader(bytes.NewReader(payload), 64)
		r.ReadNext(schema)
		return r.Error
	})
}

func TestSecurity_ReadMapCB_TruncatedBlock(t *testing.T) {
	defer ConfigTeardown()

	payload := craftTruncatedBlock(t, int64(1)<<40)
	schema := avro.MustParse(`{"type":"map","values":"long"}`)

	assertFastError(t, func() error {
		r := avro.NewReader(bytes.NewReader(payload), 64)
		r.ReadNext(schema)
		return r.Error
	})
}

// TestSecurity_ArrayDecoder_LargeSingleBlock guards against a correctness
// regression from the SEC-02 fix: growing the destination slice in bounded
// chunks (arrayGrowChunk) instead of all at once must still decode a large,
// legitimate single block correctly, spanning multiple chunk boundaries.
func TestSecurity_ArrayDecoder_LargeSingleBlock(t *testing.T) {
	defer ConfigTeardown()

	const n = 3000 // > 2 * arrayGrowChunk, so at least 3 growth steps occur.
	want := make([]int64, n)
	for i := range want {
		want[i] = int64(i)
	}

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 4096)
	w.WriteBlockHeader(int64(n), 0)
	for _, v := range want {
		w.WriteLong(v)
	}
	w.WriteBlockHeader(0, 0)
	require.NoError(t, w.Flush())

	schema := avro.MustParse(`{"type":"array","items":"long"}`)
	var got []int64
	err := avro.Unmarshal(schema, buf.Bytes(), &got)

	require.NoError(t, err)
	assert.Equal(t, want, got)
}
