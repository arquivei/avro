package avro_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/hamba/avro/v2"
)

// fuzzDecodeAPI bounds allocation per fuzz iteration so a long fuzzing run
// stays fast and does not itself exhaust memory on the machine running it,
// independent of the library's own defaults.
var fuzzDecodeAPI = avro.Config{
	MaxByteSliceSize:  1 << 20,
	MaxSliceAllocSize: 1 << 20,
}.Freeze()

// craftBlockHeaderPayload builds a single block header declaring count
// elements with no size prefix and no element data - the shape used to
// demonstrate CVE-2026-46385 (GO-2026-5046, see
// docs/seguranca-2026-07-29/README.md SEC-01/SEC-02).
func craftBlockHeaderPayload(count int64) []byte {
	buf := &bytes.Buffer{}
	w := avro.NewWriter(buf, 64)
	w.WriteBlockHeader(count, 0)
	_ = w.Flush()
	return buf.Bytes()
}

// FuzzDecode is discovery/regression coverage for the decoders: an arbitrary
// payload decoded against a fixed, moderately complex schema (array, map,
// union, enum, nested record) must never panic or hang, regardless of how
// malformed the payload is.
func FuzzDecode(f *testing.F) {
	schemaBytes, err := os.ReadFile("testdata/superhero.avsc")
	if err != nil {
		f.Fatal(err)
	}
	schema := avro.MustParse(string(schemaBytes))

	if valid, err := os.ReadFile("testdata/superhero.bin"); err == nil {
		f.Add(valid)
	}
	f.Add(craftBlockHeaderPayload(1 << 40))
	f.Add(craftBlockHeaderPayload(-1))
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		var out any
		_ = fuzzDecodeAPI.Unmarshal(schema, data, &out)
	})
}

// FuzzParseSchema is discovery/regression coverage for the schema parser:
// arbitrary JSON must never panic, regardless of how it is structured.
func FuzzParseSchema(f *testing.F) {
	for _, path := range []string{
		"testdata/schema.avsc",
		"testdata/bad-schema.avsc",
		"testdata/superhero.avsc",
		"testdata/superhero-part1.avsc",
		"testdata/superhero-part2.avsc",
		"testdata/concurrent-schema.avsc",
	} {
		if b, err := os.ReadFile(path); err == nil {
			f.Add(string(b))
		}
	}
	f.Add(`"long"`)
	f.Add(`{}`)
	f.Add(`{"type":"record","name":"a","fields":[]}`)

	f.Fuzz(func(t *testing.T, schemaJSON string) {
		// A fresh cache per call, so a long fuzzing run does not grow the
		// package-level DefaultSchemaCache without bound.
		cache := &avro.SchemaCache{}
		_, _ = avro.ParseWithCache(schemaJSON, "", cache)
	})
}
