package merkletrie

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Encoding defines a canonical byte representation for values of T.
// CompatibilityID must change whenever the representation or its meaning
// changes. Encode must be deterministic, and Decode must reject non-canonical
// representations.
type Encoding[T any] interface {
	CompatibilityID() Digest
	Encode(T) ([]byte, error)
	Decode([]byte) (T, error)
}

// NewEncoding adapts canonical encode and decode functions into an Encoding.
// The compatibility ID must uniquely identify the representation and meaning.
func NewEncoding[T any](id Digest, encode func(T) ([]byte, error), decode func([]byte) (T, error)) (Encoding[T], error) {
	if id == (Digest{}) {
		return nil, fmt.Errorf("%w: zero encoding compatibility ID", ErrInvalidCodec)
	}
	if encode == nil {
		return nil, fmt.Errorf("%w: nil encode function", ErrInvalidCodec)
	}
	if decode == nil {
		return nil, fmt.Errorf("%w: nil decode function", ErrInvalidCodec)
	}
	return builtinEncoding[T]{id: id, encode: encode, decode: decode}, nil
}

// PairCodec combines independent key and value encodings into a Codec.
// Construct one with NewCodec so invalid encodings are rejected eagerly.
type PairCodec[K, V any] struct {
	key   Encoding[K]
	value Encoding[V]
	id    Digest
}

// NewCodec combines key and value encodings. It rejects nil encodings,
// including typed nils, and zero compatibility IDs.
func NewCodec[K, V any](key Encoding[K], value Encoding[V]) (PairCodec[K, V], error) {
	if key == nil || nilValue(key) {
		return PairCodec[K, V]{}, fmt.Errorf("%w: nil key encoding", ErrInvalidCodec)
	}
	if value == nil || nilValue(value) {
		return PairCodec[K, V]{}, fmt.Errorf("%w: nil value encoding", ErrInvalidCodec)
	}
	keyID, valueID := key.CompatibilityID(), value.CompatibilityID()
	if keyID == (Digest{}) {
		return PairCodec[K, V]{}, fmt.Errorf("%w: zero key encoding compatibility ID", ErrInvalidCodec)
	}
	if valueID == (Digest{}) {
		return PairCodec[K, V]{}, fmt.Errorf("%w: zero value encoding compatibility ID", ErrInvalidCodec)
	}
	return PairCodec[K, V]{key: key, value: value, id: pairCompatibilityID(keyID, valueID)}, nil
}

// CompatibilityID implements Codec.
func (c PairCodec[K, V]) CompatibilityID() Digest { return c.id }

// EncodeKey implements Codec.
func (c PairCodec[K, V]) EncodeKey(key K) ([]byte, error) { return c.key.Encode(key) }

// DecodeKey implements Codec.
func (c PairCodec[K, V]) DecodeKey(encoded []byte) (K, error) { return c.key.Decode(encoded) }

// EncodeValue implements Codec.
func (c PairCodec[K, V]) EncodeValue(value V) ([]byte, error) { return c.value.Encode(value) }

// DecodeValue implements Codec.
func (c PairCodec[K, V]) DecodeValue(encoded []byte) (V, error) { return c.value.Decode(encoded) }

type builtinEncoding[T any] struct {
	id     Digest
	encode func(T) ([]byte, error)
	decode func([]byte) (T, error)
}

func (e builtinEncoding[T]) CompatibilityID() Digest        { return e.id }
func (e builtinEncoding[T]) Encode(value T) ([]byte, error) { return e.encode(value) }
func (e builtinEncoding[T]) Decode(encoded []byte) (T, error) {
	return e.decode(encoded)
}

// StringEncoding returns the canonical encoding of a Go string as its bytes.
func StringEncoding() Encoding[string] {
	return builtinEncoding[string]{
		id: builtinCompatibilityID("string/v1"),
		encode: func(value string) ([]byte, error) {
			return []byte(value), nil
		},
		decode: func(encoded []byte) (string, error) {
			return string(encoded), nil
		},
	}
}

// BytesEncoding returns the canonical identity encoding for byte slices.
// Both operations return a copy, so callers cannot mutate retained input.
func BytesEncoding() Encoding[[]byte] {
	return builtinEncoding[[]byte]{
		id: builtinCompatibilityID("bytes/v1"),
		encode: func(value []byte) ([]byte, error) {
			return append([]byte(nil), value...), nil
		},
		decode: func(encoded []byte) ([]byte, error) {
			return append([]byte(nil), encoded...), nil
		},
	}
}

// Uint8Encoding returns a one-byte unsigned integer encoding.
func Uint8Encoding() Encoding[uint8] {
	return fixedEncoding("uint8/be/v1", 1,
		func(value uint8, encoded []byte) { encoded[0] = value },
		func(encoded []byte) uint8 { return encoded[0] })
}

// Uint16Encoding returns a two-byte, big-endian unsigned integer encoding.
func Uint16Encoding() Encoding[uint16] {
	return fixedEncoding("uint16/be/v1", 2,
		func(value uint16, encoded []byte) { binary.BigEndian.PutUint16(encoded, value) }, binary.BigEndian.Uint16)
}

// Uint32Encoding returns a four-byte, big-endian unsigned integer encoding.
func Uint32Encoding() Encoding[uint32] {
	return fixedEncoding("uint32/be/v1", 4,
		func(value uint32, encoded []byte) { binary.BigEndian.PutUint32(encoded, value) }, binary.BigEndian.Uint32)
}

// Uint64Encoding returns an eight-byte, big-endian unsigned integer encoding.
func Uint64Encoding() Encoding[uint64] {
	return fixedEncoding("uint64/be/v1", 8,
		func(value uint64, encoded []byte) { binary.BigEndian.PutUint64(encoded, value) }, binary.BigEndian.Uint64)
}

// Int8Encoding returns a one-byte, two's-complement signed integer encoding.
func Int8Encoding() Encoding[int8] {
	return fixedEncoding("int8/twos-complement-be/v1", 1,
		func(value int8, encoded []byte) { encoded[0] = byte(value) },
		func(encoded []byte) int8 { return int8(encoded[0]) })
}

// Int16Encoding returns a two-byte, big-endian two's-complement encoding.
func Int16Encoding() Encoding[int16] {
	return fixedEncoding("int16/twos-complement-be/v1", 2,
		func(value int16, encoded []byte) { binary.BigEndian.PutUint16(encoded, uint16(value)) },
		func(encoded []byte) int16 { return int16(binary.BigEndian.Uint16(encoded)) })
}

// Int32Encoding returns a four-byte, big-endian two's-complement encoding.
func Int32Encoding() Encoding[int32] {
	return fixedEncoding("int32/twos-complement-be/v1", 4,
		func(value int32, encoded []byte) { binary.BigEndian.PutUint32(encoded, uint32(value)) },
		func(encoded []byte) int32 { return int32(binary.BigEndian.Uint32(encoded)) })
}

// Int64Encoding returns an eight-byte, big-endian two's-complement encoding.
func Int64Encoding() Encoding[int64] {
	return fixedEncoding("int64/twos-complement-be/v1", 8,
		func(value int64, encoded []byte) { binary.BigEndian.PutUint64(encoded, uint64(value)) },
		func(encoded []byte) int64 { return int64(binary.BigEndian.Uint64(encoded)) })
}

func fixedEncoding[T any](name string, width int, put func(T, []byte), get func([]byte) T) Encoding[T] {
	return builtinEncoding[T]{
		id: builtinCompatibilityID(name),
		encode: func(value T) ([]byte, error) {
			encoded := make([]byte, width)
			put(value, encoded)
			return encoded, nil
		},
		decode: func(encoded []byte) (T, error) {
			if len(encoded) != width {
				var zero T
				return zero, fmt.Errorf("merkletrie: invalid %s encoding length %d; want %d", name, len(encoded), width)
			}
			return get(encoded), nil
		},
	}
}

func builtinCompatibilityID(name string) Digest {
	hash := sha256.New()
	hash.Write([]byte("go-merkletrie/encoding/v1\x00"))
	hash.Write([]byte(name))
	var id Digest
	copy(id[:], hash.Sum(nil))
	return id
}

func pairCompatibilityID(key, value Digest) Digest {
	hash := sha256.New()
	hash.Write([]byte("go-merkletrie/codec-pair/v1\x00"))
	hash.Write(key[:])
	hash.Write(value[:])
	var id Digest
	copy(id[:], hash.Sum(nil))
	return id
}
