package avro_test

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/arquivei/avro/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are regression coverage for docs/seguranca-2026-07-30/README.md
// SEC-10 (CVE-2026-46384 / GO-2026-5047) and SEC-11 (GO-2026-5048).
//
// SEC-10 is a family of 64-bit values read from the wire and narrowed to a
// platform int before being validated. On 32-bit builds the narrowing
// truncates — (1<<32)+5 becomes 5 — so the bound is checked against a value
// the decoder never uses. Several of these payloads therefore already failed
// on amd64 before the fix; what the tests pin down is that validation happens
// on the int64, which is what makes the behaviour identical on 386/arm.
//
// SEC-11 is the unbounded cumulative growth of a decoded map.

// craftLongs builds a payload from raw Avro longs, so a test can write a
// block header that ReadBlockHeader must reject and WriteBlockHeader would
// never produce.
func craftLongs(t *testing.T, longs ...int64) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 64)
	for _, v := range longs {
		w.WriteLong(v)
	}
	require.NoError(t, w.Flush())
	return buf.Bytes()
}

// craftMap builds a valid map payload split into the given blocks, where each
// block declares its own element count and is followed by that many real
// key/value pairs.
func craftMap(t *testing.T, blocks ...int) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 1024)
	var n int
	for _, count := range blocks {
		w.WriteBlockHeader(int64(count), 0)
		for range count {
			w.WriteString(fmt.Sprintf("k%d", n))
			w.WriteLong(int64(n))
			n++
		}
	}
	w.WriteBlockHeader(0, 0)
	require.NoError(t, w.Flush())
	return buf.Bytes()
}

func TestSecurity_ReadBlockHeader_RejectsOutOfRangeHeader(t *testing.T) {
	tests := []struct {
		name  string
		longs []int64
	}{
		{
			// -math.MinInt64 is math.MinInt64: negating the count to turn the
			// "size follows" signal into a length yields a negative length,
			// which callers treat as a live block.
			name:  "count is math.MinInt64",
			longs: []int64{math.MinInt64},
		},
		{
			name:  "negated count exceeds math.MaxInt32",
			longs: []int64{-(math.MaxInt32 + 1), 8},
		},
		{
			name:  "count exceeds math.MaxInt32",
			longs: []int64{math.MaxInt32 + 1},
		},
		{
			name:  "size exceeds math.MaxInt32",
			longs: []int64{-4, math.MaxInt32 + 1},
		},
		{
			name:  "size is negative",
			longs: []int64{-4, -8},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := avro.NewReader(bytes.NewReader(craftLongs(t, test.longs...)), 64)

			gotLen, gotSize := r.ReadBlockHeader()

			assert.Error(t, r.Error)
			assert.Zero(t, gotLen)
			assert.Zero(t, gotSize)
		})
	}
}

// TestSecurity_ReadBlockHeader_AcceptsInt32Bounds guards against the SEC-10
// bound being tightened past what the Avro spec allows in practice: a header
// exactly at the int32 limit is still legal.
func TestSecurity_ReadBlockHeader_AcceptsInt32Bounds(t *testing.T) {
	tests := []struct {
		name     string
		longs    []int64
		wantLen  int64
		wantSize int64
	}{
		{
			name:    "count at math.MaxInt32",
			longs:   []int64{math.MaxInt32},
			wantLen: math.MaxInt32,
		},
		{
			name:     "negated count at math.MaxInt32 with size",
			longs:    []int64{-math.MaxInt32, math.MaxInt32},
			wantLen:  math.MaxInt32,
			wantSize: math.MaxInt32,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := avro.NewReader(bytes.NewReader(craftLongs(t, test.longs...)), 64)

			gotLen, gotSize := r.ReadBlockHeader()

			require.NoError(t, r.Error)
			assert.Equal(t, test.wantLen, gotLen)
			assert.Equal(t, test.wantSize, gotSize)
		})
	}
}

func TestSecurity_ArrayDecoder_MinInt64BlockCount(t *testing.T) {
	defer ConfigTeardown()

	payload := craftLongs(t, math.MinInt64)
	schema := `{"type":"array","items":"long"}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var got []int64
		return dec.Decode(&got)
	})
}

func TestSecurity_MapDecoder_MinInt64BlockCount(t *testing.T) {
	defer ConfigTeardown()

	payload := craftLongs(t, math.MinInt64)
	schema := `{"type":"map","values":"long"}`

	assertFastError(t, func() error {
		dec, err := avro.NewDecoder(schema, bytes.NewReader(payload))
		require.NoError(t, err)

		var got map[string]int64
		return dec.Decode(&got)
	})
}

// TestSecurity_ReadBytes_ExceedsMaxAllocSize covers the path where
// Config.MaxByteSliceSize is disabled: the length must still be rejected
// before it reaches make, which would otherwise panic or exhaust memory.
func TestSecurity_ReadBytes_ExceedsMaxAllocSize(t *testing.T) {
	defer ConfigTeardown()

	cfg := avro.Config{MaxByteSliceSize: -1}.Freeze()
	payload := craftLongs(t, int64(1)<<49)

	t.Run("bytes", func(t *testing.T) {
		r := avro.NewReader(bytes.NewReader(payload), 64, avro.WithReaderConfig(cfg))

		got := r.ReadBytes()

		assert.Error(t, r.Error)
		assert.Nil(t, got)
	})

	t.Run("string", func(t *testing.T) {
		r := avro.NewReader(bytes.NewReader(payload), 64, avro.WithReaderConfig(cfg))

		got := r.ReadString()

		assert.Error(t, r.Error)
		assert.Empty(t, got)
	})
}

// TestSecurity_GenericUnionIndex_OutOfRange pins the union index bound to the
// int64 read from the wire. Narrowed first, 1<<32 becomes 0 on 32-bit builds
// and silently selects the "null" branch of a nullable union, turning an
// encoded payload into a nil value.
func TestSecurity_GenericUnionIndex_OutOfRange(t *testing.T) {
	defer ConfigTeardown()

	schema := avro.MustParse(`["null","string"]`)
	payload := craftLongs(t, int64(1)<<32)

	r := avro.NewReader(bytes.NewReader(payload), 64)

	got := r.ReadNext(schema)

	assert.Error(t, r.Error)
	assert.Nil(t, got)
}

// TestSecurity_SkipBytes_LargeLength checks that a skip length beyond the
// available data ends in an error rather than skipping a truncated count and
// leaving the reader misaligned mid-block.
func TestSecurity_SkipBytes_LargeLength(t *testing.T) {
	defer ConfigTeardown()

	payload := append(craftLongs(t, (int64(1)<<32)+5), bytes.Repeat([]byte{0x20}, 10)...)

	t.Run("SkipBytes", func(t *testing.T) {
		r := avro.NewReader(bytes.NewReader(payload), 4)

		r.SkipBytes()

		assert.Error(t, r.Error)
	})

	t.Run("SkipString", func(t *testing.T) {
		r := avro.NewReader(bytes.NewReader(payload), 4)

		r.SkipString()

		assert.Error(t, r.Error)
	})
}

func TestSecurity_MapDecoder_ExceedMaxMapAllocSize(t *testing.T) {
	defer ConfigTeardown()

	avro.DefaultConfig = avro.Config{MaxMapAllocSize: 5}.Freeze()
	schema := `{"type":"map","values":"long"}`

	tests := []struct {
		name   string
		blocks []int
	}{
		{name: "single block", blocks: []int{10}},
		// Each block is below the limit; only the running total exceeds it.
		{name: "chunked blocks", blocks: []int{3, 3}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dec, err := avro.NewDecoder(schema, bytes.NewReader(craftMap(t, test.blocks...)))
			require.NoError(t, err)

			var got map[string]int64
			err = dec.Decode(&got)

			require.Error(t, err)
			assert.ErrorContains(t, err, "`Config.MaxMapAllocSize`")
		})
	}
}

func TestSecurity_MapDecoderUnmarshaler_ExceedMaxMapAllocSize(t *testing.T) {
	defer ConfigTeardown()

	avro.DefaultConfig = avro.Config{MaxMapAllocSize: 5}.Freeze()
	schema := `{"type":"map","values":"string"}`

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 1024)
	for range 2 {
		w.WriteBlockHeader(3, 0)
		for i := range 3 {
			w.WriteString(fmt.Sprintf("%d", i))
			w.WriteString("v")
		}
	}
	w.WriteBlockHeader(0, 0)
	require.NoError(t, w.Flush())

	dec, err := avro.NewDecoder(schema, bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)

	var got map[*textUnmarshallerInt]string
	err = dec.Decode(&got)

	require.Error(t, err)
	assert.ErrorContains(t, err, "`Config.MaxMapAllocSize`")
}

// TestSecurity_MapDecoder_WithinMaxMapAllocSize guards against the SEC-11
// limit rejecting legitimate input: a map whose cumulative count sits exactly
// on the limit, spread across blocks, must still decode.
func TestSecurity_MapDecoder_WithinMaxMapAllocSize(t *testing.T) {
	defer ConfigTeardown()

	avro.DefaultConfig = avro.Config{MaxMapAllocSize: 6}.Freeze()
	schema := `{"type":"map","values":"long"}`

	dec, err := avro.NewDecoder(schema, bytes.NewReader(craftMap(t, 3, 3)))
	require.NoError(t, err)

	var got map[string]int64
	err = dec.Decode(&got)

	require.NoError(t, err)
	assert.Equal(t, map[string]int64{
		"k0": 0, "k1": 1, "k2": 2, "k3": 3, "k4": 4, "k5": 5,
	}, got)
}

// TestSecurity_MapDecoder_DefaultIsUnbounded documents the deliberate default:
// MaxMapAllocSize is opt-in, so an unset config keeps decoding maps of any
// size. Consumers of untrusted input must set it explicitly.
func TestSecurity_MapDecoder_DefaultIsUnbounded(t *testing.T) {
	defer ConfigTeardown()

	schema := `{"type":"map","values":"long"}`

	dec, err := avro.NewDecoder(schema, bytes.NewReader(craftMap(t, 2000)))
	require.NoError(t, err)

	var got map[string]int64
	err = dec.Decode(&got)

	require.NoError(t, err)
	assert.Len(t, got, 2000)
}
