package ocf_test

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hamba/avro/v2"
	"github.com/hamba/avro/v2/ocf"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests are regression coverage for docs/seguranca-2026-07-29/README.md
// SEC-03 (a negative or implausibly large block size crashes or exhausts
// memory) and SEC-04 (a small compressed block expands to an unbounded
// decompressed size). Every payload here is a handful of bytes; a correct
// decoder rejects them in microseconds.
const dosRegressionTimeout = 5 * time.Second

// craftOCFHeader builds a minimal, valid OCF header for the given writer
// schema and codec, with a caller-chosen sync marker. Using a fixed sync
// (instead of ocf.NewEncoder's random one) lets the hand-crafted blocks
// below supply a matching sync without depending on encoder internals.
func craftOCFHeader(t *testing.T, schema string, codecName ocf.CodecName, sync [16]byte) []byte {
	t.Helper()

	meta := map[string][]byte{"avro.schema": []byte(schema)}
	if codecName != "" {
		meta["avro.codec"] = []byte(codecName)
	}

	data, err := avro.Marshal(ocf.HeaderSchema, ocf.Header{
		Magic: [4]byte{'O', 'b', 'j', 1},
		Meta:  meta,
		Sync:  sync,
	})
	require.NoError(t, err)
	return data
}

// craftBlock builds a raw OCF block: a count long, a size long (independent
// of len(payload), so a mismatch can be crafted deliberately), the payload
// bytes, and the sync marker.
func craftBlock(t *testing.T, count, size int64, payload []byte, sync [16]byte) []byte {
	t.Helper()

	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 64)
	w.WriteLong(count)
	w.WriteLong(size)
	require.NoError(t, w.Flush())

	buf.Write(payload)
	buf.Write(sync[:])
	return buf.Bytes()
}

// assertDecodeFails opens payload as an OCF stream and requires that reading
// it fails - fast, and without panicking. A goroutine + timeout + recover is
// used because, pre-fix, some of these payloads panicked (SEC-03) or hung
// consuming memory (SEC-04); either would otherwise take down the whole test
// binary or the CI job instead of failing this one test.
func assertDecodeFails(t *testing.T, payload []byte, wantSubstring string, opts ...ocf.DecoderFunc) {
	t.Helper()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic: %v", r)
			}
		}()

		dec, err := ocf.NewDecoder(bytes.NewReader(payload), opts...)
		if err != nil {
			done <- err
			return
		}
		dec.HasNext()
		done <- dec.Error()
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		if wantSubstring != "" {
			assert.Contains(t, err.Error(), wantSubstring)
		}
	case <-time.After(dosRegressionTimeout):
		t.Fatalf("decode did not return within %s - possible DoS regression (SEC-03/SEC-04)", dosRegressionTimeout)
	}
}

func TestSecurity_ReadBlock_NegativeSize(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, "", sync)
	block := craftBlock(t, 1, -1, nil, sync)

	assertDecodeFails(t, append(header, block...), "invalid block size")
}

func TestSecurity_ReadBlock_SkipBranch_NegativeSize(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, "", sync)
	// count == 0 takes the "skip block data" branch in readBlock, which
	// also allocates make([]byte, size) directly from the declared size.
	block := craftBlock(t, 0, -1, nil, sync)

	assertDecodeFails(t, append(header, block...), "invalid block size")
}

func TestSecurity_ReadBlock_SizeAboveMax(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, "", sync)
	block := craftBlock(t, 1, 1000, nil, sync)

	assertDecodeFails(t, append(header, block...), "exceeds maximum", ocf.WithMaxBlockSize(100))
}

func TestSecurity_DeflateBomb(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, ocf.Deflate, sync)

	// 2 MiB of zeros compresses to a tiny deflate block.
	raw := make([]byte, 2<<20)
	compressedBuf := &bytes.Buffer{}
	fw, err := flate.NewWriter(compressedBuf, flate.BestCompression)
	require.NoError(t, err)
	_, err = fw.Write(raw)
	require.NoError(t, err)
	require.NoError(t, fw.Close())

	compressed := compressedBuf.Bytes()
	block := craftBlock(t, 1, int64(len(compressed)), compressed, sync)

	// 1 MiB cap, 2 MiB decompressed: only the codec-level limit can catch this,
	// since the compressed block itself is well under the cap.
	assertDecodeFails(t, append(header, block...), "exceeds maximum", ocf.WithMaxBlockSize(1<<20))
}

func TestSecurity_ZstdBomb(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, ocf.ZStandard, sync)

	raw := make([]byte, 2<<20)
	enc, err := zstd.NewWriter(nil)
	require.NoError(t, err)
	compressed := enc.EncodeAll(raw, nil)
	require.NoError(t, enc.Close())

	block := craftBlock(t, 1, int64(len(compressed)), compressed, sync)

	// The error text here comes from klauspost/compress/zstd, not this
	// package, so only assert that decoding fails fast.
	assertDecodeFails(t, append(header, block...), "", ocf.WithMaxBlockSize(1<<20))
}

func TestSecurity_SnappyBomb(t *testing.T) {
	var sync [16]byte
	header := craftOCFHeader(t, `"long"`, ocf.Snappy, sync)

	// A snappy block that only declares a huge decoded length. No actual
	// compressed payload is needed: the size check happens before
	// snappy.Decode is ever called, so the trailing "CRC" is never read.
	declared := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(declared, 2_000_000_000) // ~2 GB, above the default 100 MiB cap
	snappyBlock := append(declared[:n], 0, 0, 0, 0)

	block := craftBlock(t, 1, int64(len(snappyBlock)), snappyBlock, sync)

	assertDecodeFails(t, append(header, block...), "exceeds maximum")
}

// TestSecurity_MaxBlockSize_AllowsLegitimateFile guards against a
// correctness regression: the new default limit must not reject a normal,
// legitimate OCF file.
func TestSecurity_MaxBlockSize_AllowsLegitimateFile(t *testing.T) {
	f, err := os.Open("testdata/full.avro")
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })

	dec, err := ocf.NewDecoder(f, ocf.WithMaxBlockSize(10<<20))
	require.NoError(t, err)

	var count int
	for dec.HasNext() {
		count++
		var got FullRecord
		require.NoError(t, dec.Decode(&got))
	}
	require.NoError(t, dec.Error())
	assert.Equal(t, 1, count)
}
