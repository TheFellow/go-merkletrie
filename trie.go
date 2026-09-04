package merkletrie

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
)

const (
	// ProtocolVersion identifies the persisted object and routing semantics.
	ProtocolVersion = "go-merkletrie/v1"

	strideBits = 4
	fanout     = 1 << strideBits

	// MaximumDepth is the number of four-bit routing steps in a SHA-256 digest.
	MaximumDepth = sha256.Size * 8 / strideBits
	// MaximumLeafEntries bounds the number of entries in one leaf.
	MaximumLeafEntries = 128
	// MaximumLeafBytes bounds the canonical encoding of one leaf.
	MaximumLeafBytes = 256 << 10
	// MaximumKeyBytes bounds one canonical key.
	MaximumKeyBytes = 4 << 10
	// MaximumValueBytes bounds one canonical value. Together with the key
	// bound, it leaves enough room for a complete one-entry leaf.
	MaximumValueBytes = 240 << 10
)

var (
	// ErrBound indicates that a key, value, or object exceeds a hard bound.
	ErrBound = errors.New("merkletrie: bound exceeded")
	// ErrCollision indicates distinct canonical keys with the same routing hash.
	ErrCollision = errors.New("merkletrie: key digest collision")
	// ErrCorrupt indicates malformed or internally inconsistent encoded data.
	ErrCorrupt = errors.New("merkletrie: corrupt object")
	// ErrNotFound indicates that a referenced object is unavailable.
	ErrNotFound = errors.New("merkletrie: object not found")
	// ErrInvalidCodec indicates a nil codec or invalid compatibility identity.
	ErrInvalidCodec = errors.New("merkletrie: invalid codec")
	// ErrInvalidRoot indicates a root that is malformed or belongs to another format.
	ErrInvalidRoot = errors.New("merkletrie: invalid root")
)

var (
	keyHashDomain    = []byte("go-merkletrie/key/v1\x00")
	entryHashDomain  = []byte("go-merkletrie/entry/v1\x00")
	formatHashDomain = []byte("go-merkletrie/format/v1\x00")
	emptyHashDomain  = []byte("go-merkletrie/empty/v1\x00")
)

// Digest is a SHA-256 content identifier or fingerprint.
type Digest [sha256.Size]byte

// Codec defines canonical encodings for an application's keys and values.
// CompatibilityID must change whenever either encoding's meaning changes.
// Encodings must be deterministic and canonical. Distinct logical keys must
// have distinct canonical encodings.
type Codec[K, V any] interface {
	CompatibilityID() Digest
	EncodeKey(K) ([]byte, error)
	DecodeKey([]byte) (K, error)
	EncodeValue(V) ([]byte, error)
	DecodeValue([]byte) (V, error)
}

// SemanticRoot is a shape-independent summary of the logical entries.
// Matching summaries are useful as an equality hint but are not proof of
// equality; compare entries when adversarial collisions matter.
type SemanticRoot struct {
	Count       uint64
	Fingerprint Digest
}

// Kind identifies an encoded trie object.
type Kind uint8

const (
	// KindEmpty identifies a schema-bound empty root. It is never encoded as
	// an object and never appears as a child reference.
	KindEmpty Kind = 0
	// KindLeaf is a bounded, sorted collection of entries.
	KindLeaf Kind = 1
	// KindNode is a 16-way internal node.
	KindNode Kind = 2
)

// Reference is the immutable summary stored by a parent or generation head.
// Empty tries use a format-bound KindEmpty reference; the zero value is only
// used internally for an absent child and is not a valid generation root.
type Reference struct {
	Kind     Kind
	ID       Digest
	Semantic SemanticRoot
}

type entry struct {
	key         []byte
	value       []byte
	keyDigest   Digest
	fingerprint Digest
}

type object struct {
	depth    uint8
	leaf     []entry
	children [fanout]*object
	semantic SemanticRoot
	content  Digest
	encoded  []byte
}

func (o *object) isLeaf() bool { return o != nil && o.leaf != nil }

// Tree is an immutable trie. Put and Delete return a new Tree and leave the
// receiver safe for concurrent readers. Deletion does not merge internal
// nodes, so equal logical contents may have different physical root IDs.
type Tree[K, V any] struct {
	codec         Codec[K, V]
	compatibility Digest
	format        Digest
	root          *object
}

type config struct{ namespace []byte }

// Option customizes the persisted trie format.
type Option func(*config) error

// WithNamespace separates otherwise identical codecs into independent trie
// formats. Namespace is copied and may be at most MaximumKeyBytes long.
func WithNamespace(namespace []byte) Option {
	return func(config *config) error {
		if len(namespace) > MaximumKeyBytes {
			return fmt.Errorf("%w: namespace length %d", ErrBound, len(namespace))
		}
		config.namespace = bytes.Clone(namespace)
		return nil
	}
}

// New constructs an empty trie. A zero compatibility ID is rejected because
// it cannot safely distinguish an application's encoding protocol.
func New[K, V any](codec Codec[K, V], options ...Option) (Tree[K, V], error) {
	if codec == nil || nilValue(codec) {
		return Tree[K, V]{}, fmt.Errorf("%w: nil codec", ErrInvalidCodec)
	}
	var config config
	for _, option := range options {
		if option == nil {
			return Tree[K, V]{}, fmt.Errorf("%w: nil option", ErrCorrupt)
		}
		if err := option(&config); err != nil {
			return Tree[K, V]{}, err
		}
	}
	compatibility := codec.CompatibilityID()
	if compatibility == (Digest{}) {
		return Tree[K, V]{}, fmt.Errorf("%w: zero compatibility ID", ErrInvalidCodec)
	}
	return Tree[K, V]{codec: codec, compatibility: compatibility, format: deriveFormatID(compatibility, config.namespace)}, nil
}

func nilValue(value any) bool {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// Root returns the physical root reference. Empty roots are bound to FormatID
// and are therefore not the zero Reference. Equal IDs prove equal encoded
// shape and contents.
func (t Tree[K, V]) Root() Reference {
	if t.root == nil {
		return emptyReference(t.format)
	}
	return objectReference(t.root)
}

// CompatibilityID returns the encoding identity bound into every object.
func (t Tree[K, V]) CompatibilityID() Digest { return t.compatibility }

// FormatID identifies the complete persisted protocol, including codec,
// namespace, routing parameters, and hard limits.
func (t Tree[K, V]) FormatID() Digest { return t.format }

// Len returns the number of logical entries.
func (t Tree[K, V]) Len() uint64 { return t.Root().Semantic.Count }

// Height returns the longest internal-node path to a leaf.
func (t Tree[K, V]) Height() int { return objectHeight(t.root) }

func objectHeight(o *object) int {
	if o == nil || o.isLeaf() {
		return 0
	}
	h := 0
	for _, child := range o.children {
		h = max(h, 1+objectHeight(child))
	}
	return h
}

// Lookup returns the value associated with key.
func (t Tree[K, V]) Lookup(key K) (value V, found bool, err error) {
	encoded, err := t.encodeKey(key)
	if err != nil {
		return value, false, err
	}
	digest := keyDigest(t.format, encoded)
	o := t.root
	for o != nil && !o.isLeaf() {
		o = o.children[digestNibble(digest, int(o.depth))]
	}
	if o == nil {
		return value, false, nil
	}
	i, found, collision := leafSearch(o.leaf, digest, encoded)
	if collision {
		return value, false, ErrCollision
	}
	if !found {
		return value, false, nil
	}
	value, err = t.codec.DecodeValue(bytes.Clone(o.leaf[i].value))
	if err != nil {
		return value, false, fmt.Errorf("decode value: %w", err)
	}
	return value, true, nil
}

// Put inserts or replaces key. Identical canonical key/value bytes preserve
// the root and report changed=false.
func (t Tree[K, V]) Put(key K, value V) (Tree[K, V], bool, error) {
	encodedKey, err := t.encodeKey(key)
	if err != nil {
		return t, false, err
	}
	encodedValue, err := t.encodeValue(value)
	if err != nil {
		return t, false, err
	}
	e := newEntry(t.format, encodedKey, encodedValue)
	root, changed, err := putObject(t.format, t.root, 0, e)
	if err != nil || !changed {
		return t, changed, err
	}
	return Tree[K, V]{codec: t.codec, compatibility: t.compatibility, format: t.format, root: root}, true, nil
}

// Delete removes key. A missing key preserves the root and reports
// changed=false. Internal nodes are deliberately not merged.
func (t Tree[K, V]) Delete(key K) (Tree[K, V], bool, error) {
	encoded, err := t.encodeKey(key)
	if err != nil {
		return t, false, err
	}
	digest := keyDigest(t.format, encoded)
	root, changed, err := deleteObject(t.format, t.root, digest, encoded)
	if err != nil || !changed {
		return t, changed, err
	}
	return Tree[K, V]{codec: t.codec, compatibility: t.compatibility, format: t.format, root: root}, true, nil
}

func (t Tree[K, V]) encodeKey(key K) ([]byte, error) {
	if t.codec == nil || t.format == (Digest{}) {
		return nil, fmt.Errorf("%w: uninitialized tree", ErrCorrupt)
	}
	b, err := t.codec.EncodeKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode key: %w", err)
	}
	if len(b) > MaximumKeyBytes {
		return nil, fmt.Errorf("%w: canonical key length %d", ErrBound, len(b))
	}
	decoded, err := t.codec.DecodeKey(bytes.Clone(b))
	if err != nil {
		return nil, fmt.Errorf("%w: codec cannot decode encoded key: %v", ErrInvalidCodec, err)
	}
	roundTrip, err := t.codec.EncodeKey(decoded)
	if err != nil || !bytes.Equal(roundTrip, b) {
		return nil, fmt.Errorf("%w: key encoding is not canonical", ErrInvalidCodec)
	}
	return bytes.Clone(b), nil
}

func (t Tree[K, V]) encodeValue(value V) ([]byte, error) {
	b, err := t.codec.EncodeValue(value)
	if err != nil {
		return nil, fmt.Errorf("encode value: %w", err)
	}
	if len(b) > MaximumValueBytes {
		return nil, fmt.Errorf("%w: canonical value length %d", ErrBound, len(b))
	}
	decoded, err := t.codec.DecodeValue(bytes.Clone(b))
	if err != nil {
		return nil, fmt.Errorf("%w: codec cannot decode encoded value: %v", ErrInvalidCodec, err)
	}
	roundTrip, err := t.codec.EncodeValue(decoded)
	if err != nil || !bytes.Equal(roundTrip, b) {
		return nil, fmt.Errorf("%w: value encoding is not canonical", ErrInvalidCodec)
	}
	return bytes.Clone(b), nil
}

func newEntry(compatibility Digest, key, value []byte) entry {
	e := entry{key: bytes.Clone(key), value: bytes.Clone(value)}
	e.keyDigest = keyDigest(compatibility, e.key)
	e.fingerprint = entryFingerprint(compatibility, e.key, e.value)
	return e
}

func putObject(compatibility Digest, o *object, depth uint8, e entry) (*object, bool, error) {
	if depth > MaximumDepth {
		return nil, false, ErrCollision
	}
	if o == nil {
		leaf, err := buildLeaf(compatibility, depth, []entry{e})
		return leaf, true, err
	}
	if o.depth != depth || len(o.encoded) == 0 {
		return nil, false, fmt.Errorf("%w: invalid object depth", ErrCorrupt)
	}
	if o.isLeaf() {
		i, found, collision := leafSearch(o.leaf, e.keyDigest, e.key)
		if collision {
			return nil, false, ErrCollision
		}
		entries := slices.Clone(o.leaf)
		if found {
			if bytes.Equal(entries[i].value, e.value) {
				return o, false, nil
			}
			entries[i] = e
		} else {
			entries = append(entries, entry{})
			copy(entries[i+1:], entries[i:])
			entries[i] = e
		}
		built, err := buildObject(compatibility, depth, entries)
		return built, true, err
	}
	if depth >= MaximumDepth {
		return nil, false, ErrCollision
	}
	slot := digestNibble(e.keyDigest, int(depth))
	child, changed, err := putObject(compatibility, o.children[slot], depth+1, e)
	if err != nil || !changed {
		return o, changed, err
	}
	children := o.children
	children[slot] = child
	node, err := buildNode(compatibility, depth, children)
	return node, true, err
}

func deleteObject(compatibility Digest, o *object, digest Digest, key []byte) (*object, bool, error) {
	if o == nil {
		return nil, false, nil
	}
	if o.isLeaf() {
		i, found, collision := leafSearch(o.leaf, digest, key)
		if collision {
			return o, false, ErrCollision
		}
		if !found {
			return o, false, nil
		}
		entries := slices.Delete(slices.Clone(o.leaf), i, i+1)
		if len(entries) == 0 {
			return nil, true, nil
		}
		leaf, err := buildLeaf(compatibility, o.depth, entries)
		return leaf, true, err
	}
	slot := digestNibble(digest, int(o.depth))
	child, changed, err := deleteObject(compatibility, o.children[slot], digest, key)
	if err != nil || !changed {
		return o, changed, err
	}
	children := o.children
	children[slot] = child
	for _, remaining := range children {
		if remaining != nil {
			node, buildErr := buildNode(compatibility, o.depth, children)
			return node, true, buildErr
		}
	}
	return nil, true, nil
}

func buildObject(compatibility Digest, depth uint8, entries []entry) (*object, error) {
	if len(entries) <= MaximumLeafEntries && leafEncodedSize(entries) <= MaximumLeafBytes {
		return buildLeaf(compatibility, depth, entries)
	}
	if depth >= MaximumDepth {
		return nil, ErrCollision
	}
	var children [fanout]*object
	for start := 0; start < len(entries); {
		slot := digestNibble(entries[start].keyDigest, int(depth))
		end := start + 1
		for end < len(entries) && digestNibble(entries[end].keyDigest, int(depth)) == slot {
			end++
		}
		child, err := buildObject(compatibility, depth+1, entries[start:end])
		if err != nil {
			return nil, err
		}
		children[slot] = child
		start = end
	}
	return buildNode(compatibility, depth, children)
}

func buildLeaf(compatibility Digest, depth uint8, entries []entry) (*object, error) {
	if len(entries) == 0 || len(entries) > MaximumLeafEntries || leafEncodedSize(entries) > MaximumLeafBytes {
		return nil, fmt.Errorf("%w: invalid leaf size", ErrBound)
	}
	o := &object{depth: depth, leaf: slices.Clone(entries)}
	for i, e := range o.leaf {
		if len(e.key) > MaximumKeyBytes || len(e.value) > MaximumValueBytes ||
			e.keyDigest != keyDigest(compatibility, e.key) || e.fingerprint != entryFingerprint(compatibility, e.key, e.value) ||
			i > 0 && bytes.Compare(o.leaf[i-1].keyDigest[:], e.keyDigest[:]) >= 0 {
			return nil, fmt.Errorf("%w: invalid leaf entry", ErrCorrupt)
		}
		o.semantic.Count++
		o.semantic.Fingerprint = fingerprintAdd(o.semantic.Fingerprint, e.fingerprint)
	}
	o.encoded = encodeLeaf(compatibility, o)
	o.content = sha256.Sum256(o.encoded)
	return o, nil
}

func buildNode(compatibility Digest, depth uint8, children [fanout]*object) (*object, error) {
	if int(depth) >= MaximumDepth {
		return nil, fmt.Errorf("%w: node depth", ErrBound)
	}
	o := &object{depth: depth, children: children}
	for _, child := range children {
		if child == nil {
			continue
		}
		if child.depth != depth+1 || math.MaxUint64-o.semantic.Count < child.semantic.Count {
			return nil, fmt.Errorf("%w: child summary", ErrCorrupt)
		}
		o.semantic.Count += child.semantic.Count
		o.semantic.Fingerprint = fingerprintAdd(o.semantic.Fingerprint, child.semantic.Fingerprint)
	}
	if o.semantic.Count == 0 {
		return nil, fmt.Errorf("%w: empty node", ErrCorrupt)
	}
	o.encoded = encodeNode(compatibility, o)
	o.content = sha256.Sum256(o.encoded)
	return o, nil
}

func keyDigest(compatibility Digest, key []byte) Digest {
	h := sha256.New()
	h.Write(keyHashDomain)
	h.Write(compatibility[:])
	h.Write(key)
	var result Digest
	copy(result[:], h.Sum(nil))
	return result
}

func entryFingerprint(compatibility Digest, key, value []byte) Digest {
	h := sha256.New()
	h.Write(entryHashDomain)
	h.Write(compatibility[:])
	writeUvarint(h, uint64(len(key)))
	h.Write(key)
	writeUvarint(h, uint64(len(value)))
	h.Write(value)
	var result Digest
	copy(result[:], h.Sum(nil))
	return result
}

func fingerprintAdd(a, b Digest) Digest {
	var carry uint16
	for i := len(a) - 1; i >= 0; i-- {
		sum := uint16(a[i]) + uint16(b[i]) + carry
		a[i] = byte(sum)
		carry = sum >> 8
	}
	return a
}

func digestNibble(d Digest, depth int) int {
	b := d[depth/2]
	if depth%2 == 0 {
		return int(b >> 4)
	}
	return int(b & 0x0f)
}

func leafSearch(entries []entry, digest Digest, key []byte) (index int, found, collision bool) {
	i, ok := slices.BinarySearchFunc(entries, digest, func(e entry, target Digest) int {
		return bytes.Compare(e.keyDigest[:], target[:])
	})
	if !ok {
		return i, false, false
	}
	if !bytes.Equal(entries[i].key, key) {
		return i, false, true
	}
	return i, true, false
}

func objectReference(o *object) Reference {
	kind := KindNode
	if o.isLeaf() {
		kind = KindLeaf
	}
	return Reference{Kind: kind, ID: o.content, Semantic: o.semantic}
}

func deriveFormatID(compatibility Digest, namespace []byte) Digest {
	h := sha256.New()
	h.Write(formatHashDomain)
	h.Write(compatibility[:])
	writeUvarint(h, uint64(len(namespace)))
	h.Write(namespace)
	writeUvarint(h, strideBits)
	writeUvarint(h, MaximumDepth)
	writeUvarint(h, MaximumLeafEntries)
	writeUvarint(h, MaximumLeafBytes)
	writeUvarint(h, MaximumKeyBytes)
	writeUvarint(h, MaximumValueBytes)
	var result Digest
	copy(result[:], h.Sum(nil))
	return result
}

func emptyReference(format Digest) Reference {
	h := sha256.New()
	h.Write(emptyHashDomain)
	h.Write(format[:])
	var id Digest
	copy(id[:], h.Sum(nil))
	return Reference{Kind: KindEmpty, ID: id}
}
