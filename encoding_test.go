package merkletrie

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

type testEncoding[T any] struct{ id Digest }

func (e *testEncoding[T]) CompatibilityID() Digest            { return e.id }
func (e *testEncoding[T]) Encode(value T) ([]byte, error)     { return nil, nil }
func (e *testEncoding[T]) Decode([]byte) (value T, err error) { return value, nil }

func TestNewCodecValidation(t *testing.T) {
	validID := Digest{1}
	valid := &testEncoding[string]{id: validID}
	var typedNil *testEncoding[string]

	tests := []struct {
		name  string
		key   Encoding[string]
		value Encoding[string]
	}{
		{name: "nil key", value: valid},
		{name: "typed nil key", key: typedNil, value: valid},
		{name: "nil value", key: valid},
		{name: "typed nil value", key: valid, value: typedNil},
		{name: "zero key ID", key: &testEncoding[string]{}, value: valid},
		{name: "zero value ID", key: valid, value: &testEncoding[string]{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewCodec(test.key, test.value); !errors.Is(err, ErrInvalidCodec) {
				t.Fatalf("NewCodec() error = %v, want ErrInvalidCodec", err)
			}
		})
	}
}

func TestNewEncodingValidation(t *testing.T) {
	id := Digest{1}
	encode := func(value string) ([]byte, error) { return []byte(value), nil }
	decode := func(encoded []byte) (string, error) { return string(encoded), nil }

	if _, err := NewEncoding(Digest{}, encode, decode); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("zero ID error = %v, want ErrInvalidCodec", err)
	}
	if _, err := NewEncoding[string](id, nil, decode); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("nil encode error = %v, want ErrInvalidCodec", err)
	}
	if _, err := NewEncoding[string](id, encode, nil); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("nil decode error = %v, want ErrInvalidCodec", err)
	}
	encoding, err := NewEncoding(id, encode, decode)
	if err != nil {
		t.Fatal(err)
	}
	got, err := encoding.Decode([]byte("custom"))
	if err != nil || got != "custom" {
		t.Fatalf("Decode() = %q, %v", got, err)
	}
}

func TestPairCodec(t *testing.T) {
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	if codec.CompatibilityID() == (Digest{}) {
		t.Fatal("zero pair compatibility ID")
	}
	other, err := NewCodec(StringEncoding(), Int64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	if codec.CompatibilityID() == other.CompatibilityID() {
		t.Fatal("distinct encoding pairs have equal IDs")
	}

	tree, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	tree, changed, err := tree.Put("answer", 42)
	if err != nil || !changed {
		t.Fatalf("Put() = changed %v, error %v", changed, err)
	}
	got, found, err := tree.Lookup("answer")
	if err != nil || !found || got != 42 {
		t.Fatalf("Lookup() = %d, %v, %v", got, found, err)
	}
}

func TestBytesEncodingCopies(t *testing.T) {
	encoding := BytesEncoding()
	original := []byte{1, 2, 3}
	encoded, err := encoding.Encode(original)
	if err != nil {
		t.Fatal(err)
	}
	encoded[0] = 9
	if original[0] != 1 {
		t.Fatal("Encode retained input")
	}
	decoded, err := encoding.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] = 9
	if !bytes.Equal(decoded, []byte{9, 2, 3}) {
		t.Fatal("Decode retained input")
	}
}

func TestIntegerEncodings(t *testing.T) {
	testEncodingRoundTrip(t, Uint8Encoding(), []uint8{0, 1, math.MaxUint8}, 1)
	testEncodingRoundTrip(t, Uint16Encoding(), []uint16{0, 1, math.MaxUint16}, 2)
	testEncodingRoundTrip(t, Uint32Encoding(), []uint32{0, 1, math.MaxUint32}, 4)
	testEncodingRoundTrip(t, Uint64Encoding(), []uint64{0, 1, math.MaxUint64}, 8)
	testEncodingRoundTrip(t, Int8Encoding(), []int8{math.MinInt8, -1, 0, 1, math.MaxInt8}, 1)
	testEncodingRoundTrip(t, Int16Encoding(), []int16{math.MinInt16, -1, 0, 1, math.MaxInt16}, 2)
	testEncodingRoundTrip(t, Int32Encoding(), []int32{math.MinInt32, -1, 0, 1, math.MaxInt32}, 4)
	testEncodingRoundTrip(t, Int64Encoding(), []int64{math.MinInt64, -1, 0, 1, math.MaxInt64}, 8)
}

func testEncodingRoundTrip[T comparable](t *testing.T, encoding Encoding[T], values []T, width int) {
	t.Helper()
	for _, value := range values {
		encoded, err := encoding.Encode(value)
		if err != nil {
			t.Fatalf("Encode(%v): %v", value, err)
		}
		if len(encoded) != width {
			t.Fatalf("Encode(%v) length = %d, want %d", value, len(encoded), width)
		}
		decoded, err := encoding.Decode(encoded)
		if err != nil || decoded != value {
			t.Fatalf("Decode(Encode(%v)) = %v, %v", value, decoded, err)
		}
	}
	if _, err := encoding.Decode(make([]byte, width+1)); err == nil {
		t.Fatal("Decode accepted a non-canonical width")
	}
}
