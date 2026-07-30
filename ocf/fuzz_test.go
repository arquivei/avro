package ocf_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/arquivei/avro/v2/ocf"
)

// FuzzOCFDecode is discovery/regression coverage for
// docs/seguranca-2026-07-29/README.md SEC-03/SEC-04: decoding an arbitrary byte sequence as an OCF file must
// never panic, hang, or allocate unbounded memory, regardless of how
// malformed or hostile the input is.
func FuzzOCFDecode(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".avro" {
				continue
			}
			if b, err := os.ReadFile(filepath.Join("testdata", e.Name())); err == nil {
				f.Add(b)
			}
		}
	}
	f.Add([]byte{})
	f.Add([]byte("Obj\x01"))

	// A small cap keeps each fuzz iteration fast and bounded regardless of
	// what the fuzzer discovers; the seeded .avro files are all a few KB.
	const maxBlockSize = 1 << 20

	f.Fuzz(func(t *testing.T, data []byte) {
		dec, err := ocf.NewDecoder(bytes.NewReader(data), ocf.WithMaxBlockSize(maxBlockSize))
		if err != nil {
			return
		}
		for dec.HasNext() {
			var out any
			if dec.Decode(&out) != nil {
				return
			}
		}
	})
}
