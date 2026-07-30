# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Full writeup, evidence, and PoCs for every item below:
[`docs/seguranca-2026-07-29/README.md`](docs/seguranca-2026-07-29/README.md).

### Security

- Fixed a denial-of-service in the array and map decoders (`CVE-2026-46385`,
  `GO-2026-5046`): a block header declaring a large element count, followed
  by truncated or absent data, made the decoder spin for the full declared
  count instead of stopping at the first read error. Affected
  `sliceSkipDecoder`, `mapSkipDecoder`, `mapDecoderUnmarshaler`, and the
  public `Reader.ReadArrayCB`/`Reader.ReadMapCB`.
- Fixed unbounded up-front allocation in the array decoder: it now grows the
  destination slice in bounded increments instead of allocating for the
  entire declared element count before reading any data.
- Fixed a panic and unbounded allocation in the OCF decoder from an
  unvalidated block size (negative or implausibly large `size` in the block
  header caused `runtime error: makeslice: len out of range` or an
  out-of-memory condition).
- Fixed decompression-bomb exposure in all three OCF compression codecs
  (Deflate, Snappy, ZStandard): decompressed output size is now bounded.
- Fixed code-injection exposure in `gen`/`avrogen` when
  `avro.SkipNameValidation` is set: a hostile field name, enum symbol, or
  record/enum name could break out of the generated Go source. Struct tags
  and enum symbol values are now escaped; type, field, and enum identifiers
  are now sanitized to valid Go identifiers; malformed generated code is no
  longer written to disk.
- Fixed a memory-aliasing bug in `Reader.ReadBytes`'s fast path: appending to
  a returned `[]byte` could write into the buffer backing a subsequent read,
  silently corrupting it.
- Bumped `github.com/klauspost/compress` to v1.18.7 (`GO-2026-5841`, OOB read
  in `s2.NewDict`; not reachable via this library's own use of the package,
  but affected consumers resolving this module's dependency).

### Added

- `ocf.WithMaxBlockSize` to bound a block's declared pre-decompression size
  and a codec's decompressed output size. Defaults to 100 MiB; a value `<= 0`
  disables the limit.
- `govulncheck` as a CI step.
- Fuzz targets `FuzzDecode`, `FuzzParseSchema` (package root), and
  `FuzzOCFDecode` (`ocf`), seeded with the existing `testdata` fixtures and
  the payloads from the fixes above.
- `.github/workflows/fuzz.yml`: a scheduled (and manually triggerable) job
  running each fuzz target for 10 minutes.

### Changed

- CI test matrix updated from Go 1.24/1.25 to 1.25/1.26 (1.24 is EOL). The
  module's declared minimum Go version (`go.mod`) is unchanged.
- `mise.toml` now pins a Go version.
- CI's pinned `golangci-lint` bumped from v2.6.2 to v2.12.2; the old version
  didn't run cleanly against the Go 1.26 toolchain.
- Replaced the deprecated `reflect.Ptr` with `reflect.Pointer` throughout
  (`codec.go`, `codec_dynamic.go`, `codec_fixed.go`, `codec_native.go`,
  `codec_union.go`, `codec_record.go`). No behavior change.
- CI's "Setup gotestsum" step now runs `go install gotest.tools/gotestsum` directly
  instead of the `gertd/action-gotestsum` third-party action, whose repository
  was removed from GitHub.

### Documented, not fixed

- `Reader.ReadArrayCB`, called directly with a callback that never reads
  from the passed `*Reader`, can still iterate the full declared element
  count. Not reachable through any of this library's own decode paths (the
  only internal caller, `Reader.ReadNext`, always reads); the godoc now
  states the requirement explicitly.
