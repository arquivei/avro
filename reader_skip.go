package avro

import "math"

// SkipNBytesInt64 skips the given number of bytes in the reader.
//
// Use this instead of SkipNBytes for a count read from the wire: narrowing to
// a platform int first would let a count above the int range truncate on
// 32-bit builds — e.g. (1<<32)+5 becomes 5 — skipping too few bytes and
// leaving the reader misaligned on data the caller believes it has consumed.
func (r *Reader) SkipNBytesInt64(n int64) {
	for n > 0 {
		chunk := min(n, math.MaxInt32)
		r.SkipNBytes(int(chunk))
		if r.Error != nil {
			return
		}
		n -= chunk
	}
}

// SkipNBytes skips the given number of bytes in the reader.
func (r *Reader) SkipNBytes(n int) {
	read := 0
	for read < n {
		if r.head == r.tail {
			if !r.loadMore() {
				return
			}
		}

		if read+r.tail-r.head < n {
			read += r.tail - r.head
			r.head = r.tail
			continue
		}

		r.head += n - read
		read += n - read
	}
}

// SkipBool skips a Bool in the reader.
func (r *Reader) SkipBool() {
	_ = r.readByte()
}

// SkipInt skips an Int in the reader.
func (r *Reader) SkipInt() {
	var n int
	for r.Error == nil && n < maxIntBufSize {
		b := r.readByte()
		if b&0x80 == 0 {
			break
		}
		n++
	}
}

// SkipLong skips a Long in the reader.
func (r *Reader) SkipLong() {
	var n int
	for r.Error == nil && n < maxLongBufSize {
		b := r.readByte()
		if b&0x80 == 0 {
			break
		}
		n++
	}
}

// SkipFloat skips a Float in the reader.
func (r *Reader) SkipFloat() {
	r.SkipNBytes(4)
}

// SkipDouble skips a Double in the reader.
func (r *Reader) SkipDouble() {
	r.SkipNBytes(8)
}

// SkipString skips a String in the reader.
func (r *Reader) SkipString() {
	size := r.ReadLong()
	if size <= 0 {
		return
	}
	r.SkipNBytesInt64(size)
}

// SkipBytes skips Bytes in the reader.
func (r *Reader) SkipBytes() {
	size := r.ReadLong()
	if size <= 0 {
		return
	}
	r.SkipNBytesInt64(size)
}
