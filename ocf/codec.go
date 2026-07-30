package ocf

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

// CodecName represents a compression codec name.
type CodecName string

// Supported compression codecs.
const (
	Null      CodecName = "null"
	Deflate   CodecName = "deflate"
	Snappy    CodecName = "snappy"
	ZStandard CodecName = "zstandard"
)

type codecOptions struct {
	DeflateCompressionLevel int
	ZStandardOptions        zstdOptions
	// MaxDecodedSize limits how many bytes a codec's Decode may produce.
	// <= 0 means no limit. Populated from Decoder's MaxBlockSize; unused
	// when a codec is built for encoding.
	MaxDecodedSize int64
}

// readAllLimited reads all of r, failing once more than max bytes have been
// produced. max <= 0 means no limit. This guards decompression codecs
// against decompression-bomb payloads that expand a small input into an
// arbitrarily large output.
func readAllLimited(r io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		return io.ReadAll(r)
	}

	data, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxSize {
		return nil, fmt.Errorf("decompressed size exceeds maximum of %d bytes", maxSize)
	}
	return data, nil
}

type zstdOptions struct {
	EOptions []zstd.EOption
	DOptions []zstd.DOption
	// Encoder and Decoder allow sharing pre-created instances across multiple codecs.
	// When set, EOptions/DOptions are ignored for that component.
	Encoder *zstd.Encoder
	Decoder *zstd.Decoder
}

func resolveCodec(name CodecName, codecOpts codecOptions) (Codec, error) {
	switch name {
	case Null, "":
		return &NullCodec{}, nil

	case Deflate:
		return &DeflateCodec{compLvl: codecOpts.DeflateCompressionLevel, maxDecodedSize: codecOpts.MaxDecodedSize}, nil

	case Snappy:
		return &SnappyCodec{maxDecodedSize: codecOpts.MaxDecodedSize}, nil

	case ZStandard:
		return newZStandardCodec(codecOpts.ZStandardOptions, codecOpts.MaxDecodedSize), nil

	default:
		return nil, fmt.Errorf("unknown codec %s", name)
	}
}

// Codec represents a compression codec.
type Codec interface {
	// Decode decodes the given bytes.
	Decode([]byte) ([]byte, error)
	// Encode encodes the given bytes.
	Encode([]byte) []byte
}

// NullCodec is a no op codec.
type NullCodec struct{}

// Decode decodes the given bytes.
func (*NullCodec) Decode(b []byte) ([]byte, error) {
	return b, nil
}

// Encode encodes the given bytes.
func (*NullCodec) Encode(b []byte) []byte {
	return b
}

// DeflateCodec is a flate compression codec.
type DeflateCodec struct {
	compLvl        int
	maxDecodedSize int64
}

// Decode decodes the given bytes.
func (c *DeflateCodec) Decode(b []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewBuffer(b))
	data, err := readAllLimited(r, c.maxDecodedSize)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	_ = r.Close()

	return data, nil
}

// Encode encodes the given bytes.
func (c *DeflateCodec) Encode(b []byte) []byte {
	data := bytes.NewBuffer(make([]byte, 0, len(b)))

	w, _ := flate.NewWriter(data, c.compLvl)
	_, _ = w.Write(b)
	_ = w.Close()

	return data.Bytes()
}

// SnappyCodec is a snappy compression codec.
type SnappyCodec struct {
	maxDecodedSize int64
}

// Decode decodes the given bytes.
func (c *SnappyCodec) Decode(b []byte) ([]byte, error) {
	l := len(b)
	if l < 5 {
		return nil, errors.New("block does not contain snappy checksum")
	}

	block := b[:l-4]
	if c.maxDecodedSize > 0 {
		decodedLen, err := snappy.DecodedLen(block)
		if err != nil {
			return nil, err
		}
		if int64(decodedLen) > c.maxDecodedSize {
			return nil, fmt.Errorf("decompressed size exceeds maximum of %d bytes", c.maxDecodedSize)
		}
	}

	dst, err := snappy.Decode(nil, block)
	if err != nil {
		return nil, err
	}

	crc := binary.BigEndian.Uint32(b[l-4:])
	if crc32.ChecksumIEEE(dst) != crc {
		return nil, errors.New("snappy checksum mismatch")
	}

	return dst, nil
}

// Encode encodes the given bytes.
func (*SnappyCodec) Encode(b []byte) []byte {
	dst := snappy.Encode(nil, b)

	dst = append(dst, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(dst[len(dst)-4:], crc32.ChecksumIEEE(b))

	return dst
}

// ZStandardCodec is a zstandard compression codec.
type ZStandardCodec struct {
	decoder       *zstd.Decoder
	encoder       *zstd.Encoder
	sharedDecoder bool // true if decoder was provided externally and should not be closed
	sharedEncoder bool // true if encoder was provided externally and should not be closed
}

func newZStandardCodec(opts zstdOptions, maxDecodedSize int64) *ZStandardCodec {
	var decoder *zstd.Decoder
	var encoder *zstd.Encoder
	var sharedDecoder, sharedEncoder bool

	if opts.Decoder != nil {
		// The decoder was created outside of this codec (see
		// WithZStandardDecoder), so DOptions - including any max-memory
		// limit derived from WithMaxBlockSize - cannot be applied here.
		decoder = opts.Decoder
		sharedDecoder = true
	} else {
		dOptions := opts.DOptions
		if maxDecodedSize > 0 {
			// Prepended so an explicit WithZStandardDecoderOptions call
			// still takes precedence over this default.
			dOptions = append([]zstd.DOption{zstd.WithDecoderMaxMemory(uint64(maxDecodedSize))}, dOptions...)
		}
		decoder, _ = zstd.NewReader(nil, dOptions...)
	}

	if opts.Encoder != nil {
		encoder = opts.Encoder
		sharedEncoder = true
	} else {
		encoder, _ = zstd.NewWriter(nil, opts.EOptions...)
	}

	return &ZStandardCodec{
		decoder:       decoder,
		encoder:       encoder,
		sharedDecoder: sharedDecoder,
		sharedEncoder: sharedEncoder,
	}
}

// Decode decodes the given bytes.
func (zstdCodec *ZStandardCodec) Decode(b []byte) ([]byte, error) {
	defer func() { _ = zstdCodec.decoder.Reset(nil) }()
	return zstdCodec.decoder.DecodeAll(b, nil)
}

// Encode encodes the given bytes.
func (zstdCodec *ZStandardCodec) Encode(b []byte) []byte {
	defer zstdCodec.encoder.Reset(nil)
	return zstdCodec.encoder.EncodeAll(b, nil)
}

// Close closes the zstandard encoder and decoder, releasing resources.
// Shared instances (provided via WithZStandardEncoder/WithZStandardDecoder) are not closed.
func (zstdCodec *ZStandardCodec) Close() error {
	if zstdCodec.decoder != nil && !zstdCodec.sharedDecoder {
		zstdCodec.decoder.Close()
	}
	if zstdCodec.encoder != nil && !zstdCodec.sharedEncoder {
		return zstdCodec.encoder.Close()
	}
	return nil
}
