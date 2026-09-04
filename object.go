package merkletrie

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"slices"
)

const (
	objectHeaderBytes   = 8
	objectFormatVersion = 1
	leafHeaderBytes     = objectHeaderBytes + sha256.Size + 1 + 2 + 8 + sha256.Size
	nodeHeaderBytes     = objectHeaderBytes + sha256.Size + 1 + 1 + 8 + sha256.Size + 1
	childBytes          = 1 + 1 + 8 + sha256.Size + sha256.Size
)

var objectSignature = [4]byte{'G', 'M', 'T', 'R'}

// EncodedEntry is one canonical key/value pair in a decoded leaf. Its byte
// slices are detached from both the tree and input payload.
type EncodedEntry struct {
	Key   []byte
	Value []byte
}

// ChildReference is one occupied slot in an internal node.
type ChildReference struct {
	Slot      uint8
	Reference Reference
}

// EncodedObject is a validated, content-addressed object ready for storage.
// Payload and entry bytes are detached from the tree.
type EncodedObject struct {
	Format   Digest
	Kind     Kind
	ID       Digest
	Depth    uint8
	Semantic SemanticRoot
	Entries  []EncodedEntry
	Children []ChildReference
	Payload  []byte
}

// Objects returns each reachable object once in children-before-parents
// order, suitable for idempotent persistence before publishing Root.
func (t Tree[K, V]) Objects() []EncodedObject {
	objects := make([]EncodedObject, 0)
	seen := make(map[Digest]struct{})
	var visit func(*object)
	visit = func(o *object) {
		if o == nil {
			return
		}
		if _, ok := seen[o.content]; ok {
			return
		}
		if !o.isLeaf() {
			for _, child := range o.children {
				visit(child)
			}
		}
		seen[o.content] = struct{}{}
		objects = append(objects, objectDocument(t.format, o))
	}
	visit(t.root)
	return objects
}

func objectDocument(format Digest, o *object) EncodedObject {
	ref := objectReference(o)
	document := EncodedObject{
		Format:   format,
		Kind:     ref.Kind,
		ID:       ref.ID,
		Depth:    o.depth,
		Semantic: ref.Semantic,
		Payload:  bytes.Clone(o.encoded),
	}
	if o.isLeaf() {
		document.Entries = make([]EncodedEntry, len(o.leaf))
		for i, e := range o.leaf {
			document.Entries[i] = EncodedEntry{Key: bytes.Clone(e.key), Value: bytes.Clone(e.value)}
		}
	} else {
		for slot, child := range o.children {
			if child != nil {
				document.Children = append(document.Children, ChildReference{Slot: uint8(slot), Reference: objectReference(child)})
			}
		}
	}
	return document
}

func encodeLeaf(compatibility Digest, o *object) []byte {
	b := make([]byte, 0, leafEncodedSize(o.leaf))
	b = appendObjectHeader(b, KindLeaf)
	b = append(b, compatibility[:]...)
	b = append(b, o.depth)
	b = binary.BigEndian.AppendUint16(b, uint16(len(o.leaf)))
	b = binary.BigEndian.AppendUint64(b, o.semantic.Count)
	b = append(b, o.semantic.Fingerprint[:]...)
	for _, e := range o.leaf {
		b = binary.AppendUvarint(b, uint64(len(e.key)))
		b = append(b, e.key...)
		b = binary.AppendUvarint(b, uint64(len(e.value)))
		b = append(b, e.value...)
	}
	return b
}

func leafEncodedSize(entries []entry) int {
	size := leafHeaderBytes
	for _, e := range entries {
		size += uvarintSize(uint64(len(e.key))) + len(e.key)
		size += uvarintSize(uint64(len(e.value))) + len(e.value)
	}
	return size
}

func encodeNode(compatibility Digest, o *object) []byte {
	count := 0
	for _, child := range o.children {
		if child != nil {
			count++
		}
	}
	b := make([]byte, 0, nodeHeaderBytes+count*childBytes)
	b = appendObjectHeader(b, KindNode)
	b = append(b, compatibility[:]...)
	b = append(b, o.depth, strideBits)
	b = binary.BigEndian.AppendUint64(b, o.semantic.Count)
	b = append(b, o.semantic.Fingerprint[:]...)
	b = append(b, byte(count))
	for slot, child := range o.children {
		if child == nil {
			continue
		}
		ref := objectReference(child)
		b = append(b, byte(slot), byte(ref.Kind))
		b = binary.BigEndian.AppendUint64(b, ref.Semantic.Count)
		b = append(b, ref.Semantic.Fingerprint[:]...)
		b = append(b, ref.ID[:]...)
	}
	return b
}

// DecodeObject validates a canonical object, its codec compatibility, and its
// optional expected content ID. A zero expectedID skips only the caller ID
// comparison; all other validation still applies.
func DecodeObject[K, V any](codec Codec[K, V], payload []byte, expectedID Digest, options ...Option) (EncodedObject, error) {
	if codec == nil || len(payload) < 8 || len(payload) > MaximumLeafBytes {
		return EncodedObject{}, fmt.Errorf("%w: invalid decoder or truncated object", ErrCorrupt)
	}
	tree, err := New(codec, options...)
	if err != nil {
		return EncodedObject{}, err
	}
	format := tree.format
	return decodeObjectWithFormat(codec, format, payload, expectedID)
}

func decodeObjectWithFormat[K, V any](codec Codec[K, V], format Digest, payload []byte, expectedID Digest) (EncodedObject, error) {
	if len(payload) < 8 || len(payload) > MaximumLeafBytes {
		return EncodedObject{}, fmt.Errorf("%w: invalid object length", ErrCorrupt)
	}
	actual := sha256.Sum256(payload)
	if expectedID != (Digest{}) && expectedID != actual {
		return EncodedObject{}, fmt.Errorf("%w: content ID mismatch", ErrCorrupt)
	}
	kind, err := decodeObjectHeader(payload)
	if err != nil {
		return EncodedObject{}, err
	}
	switch kind {
	case KindLeaf:
		return decodeLeaf(codec, format, payload, actual)
	case KindNode:
		return decodeNode(format, payload, actual)
	default:
		return EncodedObject{}, fmt.Errorf("%w: unknown object kind %d", ErrCorrupt, kind)
	}
}

func appendObjectHeader(dst []byte, kind Kind) []byte {
	dst = append(dst, objectSignature[:]...)
	return append(dst, objectFormatVersion, byte(kind), 0, 0)
}

func decodeObjectHeader(payload []byte) (Kind, error) {
	if len(payload) < objectHeaderBytes || !bytes.Equal(payload[:len(objectSignature)], objectSignature[:]) {
		return KindEmpty, fmt.Errorf("%w: unknown object signature", ErrCorrupt)
	}
	if payload[4] != objectFormatVersion {
		return KindEmpty, fmt.Errorf("%w: unsupported object version %d", ErrCorrupt, payload[4])
	}
	if payload[6] != 0 || payload[7] != 0 {
		return KindEmpty, fmt.Errorf("%w: nonzero reserved object header", ErrCorrupt)
	}
	kind := Kind(payload[5])
	if kind != KindLeaf && kind != KindNode {
		return KindEmpty, fmt.Errorf("%w: unknown object kind %d", ErrCorrupt, kind)
	}
	return kind, nil
}

func decodeLeaf[K, V any](codec Codec[K, V], format Digest, payload []byte, id Digest) (EncodedObject, error) {
	if len(payload) < leafHeaderBytes || len(payload) > MaximumLeafBytes || !bytes.Equal(payload[8:40], format[:]) {
		return EncodedObject{}, fmt.Errorf("%w: invalid leaf header", ErrCorrupt)
	}
	depth := payload[40]
	count := int(binary.BigEndian.Uint16(payload[41:43]))
	semantic := SemanticRoot{Count: binary.BigEndian.Uint64(payload[43:51])}
	copy(semantic.Fingerprint[:], payload[51:83])
	if depth > MaximumDepth || count == 0 || count > MaximumLeafEntries || semantic.Count != uint64(count) {
		return EncodedObject{}, fmt.Errorf("%w: invalid leaf header", ErrCorrupt)
	}
	cursor := leafHeaderBytes
	entries := make([]entry, 0, count)
	encodedEntries := make([]EncodedEntry, 0, count)
	for range count {
		keyLength, n, err := readCanonicalUvarint(payload[cursor:])
		if err != nil || keyLength > MaximumKeyBytes {
			return EncodedObject{}, fmt.Errorf("%w: invalid key length", ErrCorrupt)
		}
		cursor += n
		if keyLength > uint64(len(payload)-cursor) {
			return EncodedObject{}, fmt.Errorf("%w: truncated key", ErrCorrupt)
		}
		key := bytes.Clone(payload[cursor : cursor+int(keyLength)])
		cursor += int(keyLength)
		valueLength, n, err := readCanonicalUvarint(payload[cursor:])
		if err != nil || valueLength > MaximumValueBytes {
			return EncodedObject{}, fmt.Errorf("%w: invalid value length", ErrCorrupt)
		}
		cursor += n
		if valueLength > uint64(len(payload)-cursor) {
			return EncodedObject{}, fmt.Errorf("%w: truncated value", ErrCorrupt)
		}
		value := bytes.Clone(payload[cursor : cursor+int(valueLength)])
		cursor += int(valueLength)
		if err := validateCanonical(codec, key, value); err != nil {
			return EncodedObject{}, err
		}
		entries = append(entries, newEntry(format, key, value))
		encodedEntries = append(encodedEntries, EncodedEntry{Key: key, Value: value})
	}
	if cursor != len(payload) {
		return EncodedObject{}, fmt.Errorf("%w: trailing leaf bytes", ErrCorrupt)
	}
	leaf, err := buildLeaf(format, depth, entries)
	if err != nil || leaf.semantic != semantic || !bytes.Equal(leaf.encoded, payload) {
		return EncodedObject{}, fmt.Errorf("%w: invalid leaf encoding", ErrCorrupt)
	}
	return EncodedObject{Format: format, Kind: KindLeaf, ID: id, Depth: depth, Semantic: semantic, Entries: encodedEntries, Payload: bytes.Clone(payload)}, nil
}

func validateCanonical[K, V any](codec Codec[K, V], key, value []byte) error {
	k, err := codec.DecodeKey(bytes.Clone(key))
	if err != nil {
		return fmt.Errorf("%w: decode key: %v", ErrCorrupt, err)
	}
	reencodedKey, err := codec.EncodeKey(k)
	if err != nil || !bytes.Equal(reencodedKey, key) {
		return fmt.Errorf("%w: non-canonical key", ErrCorrupt)
	}
	v, err := codec.DecodeValue(bytes.Clone(value))
	if err != nil {
		return fmt.Errorf("%w: decode value: %v", ErrCorrupt, err)
	}
	reencodedValue, err := codec.EncodeValue(v)
	if err != nil || !bytes.Equal(reencodedValue, value) {
		return fmt.Errorf("%w: non-canonical value", ErrCorrupt)
	}
	return nil
}

func decodeNode(format Digest, payload []byte, id Digest) (EncodedObject, error) {
	if len(payload) < nodeHeaderBytes || !bytes.Equal(payload[8:40], format[:]) {
		return EncodedObject{}, fmt.Errorf("%w: invalid node header", ErrCorrupt)
	}
	depth, stride := payload[40], payload[41]
	semantic := SemanticRoot{Count: binary.BigEndian.Uint64(payload[42:50])}
	copy(semantic.Fingerprint[:], payload[50:82])
	count := int(payload[82])
	if depth >= MaximumDepth || stride != strideBits || count == 0 || count > fanout || semantic.Count == 0 || len(payload) != nodeHeaderBytes+count*childBytes {
		return EncodedObject{}, fmt.Errorf("%w: invalid node header", ErrCorrupt)
	}
	cursor, lastSlot := nodeHeaderBytes, -1
	var sum SemanticRoot
	children := make([]ChildReference, 0, count)
	for range count {
		slot, kind := int(payload[cursor]), Kind(payload[cursor+1])
		cursor += 2
		childSemantic := SemanticRoot{Count: binary.BigEndian.Uint64(payload[cursor : cursor+8])}
		cursor += 8
		copy(childSemantic.Fingerprint[:], payload[cursor:cursor+sha256.Size])
		cursor += sha256.Size
		var childID Digest
		copy(childID[:], payload[cursor:cursor+sha256.Size])
		cursor += sha256.Size
		if slot <= lastSlot || slot >= fanout || kind != KindLeaf && kind != KindNode || childSemantic.Count == 0 || childID == (Digest{}) ||
			kind == KindLeaf && childSemantic.Count > MaximumLeafEntries || kind == KindNode && depth+1 >= MaximumDepth || math.MaxUint64-sum.Count < childSemantic.Count {
			return EncodedObject{}, fmt.Errorf("%w: invalid child reference", ErrCorrupt)
		}
		lastSlot = slot
		children = append(children, ChildReference{Slot: uint8(slot), Reference: Reference{Kind: kind, ID: childID, Semantic: childSemantic}})
		sum.Count += childSemantic.Count
		sum.Fingerprint = fingerprintAdd(sum.Fingerprint, childSemantic.Fingerprint)
	}
	if sum != semantic {
		return EncodedObject{}, fmt.Errorf("%w: node semantic mismatch", ErrCorrupt)
	}
	return EncodedObject{Format: format, Kind: KindNode, ID: id, Depth: depth, Semantic: semantic, Children: children, Payload: slices.Clone(payload)}, nil
}

func writeUvarint(w io.Writer, value uint64) {
	var scratch [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(scratch[:], value)
	_, _ = w.Write(scratch[:n])
}

func readCanonicalUvarint(b []byte) (uint64, int, error) {
	value, n := binary.Uvarint(b)
	if n <= 0 || n != uvarintSize(value) {
		return 0, 0, ErrCorrupt
	}
	return value, n, nil
}

func uvarintSize(value uint64) int {
	size := 1
	for value >= 0x80 {
		value >>= 7
		size++
	}
	return size
}
