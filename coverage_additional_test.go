package merkletrie

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"
	"testing"
)

type controllableCodec struct {
	id          Digest
	encodeKey   func(string) ([]byte, error)
	decodeKey   func([]byte) (string, error)
	encodeValue func(string) ([]byte, error)
	decodeValue func([]byte) (string, error)
}

func newControllableCodec(name string) *controllableCodec {
	return &controllableCodec{
		id: sha256.Sum256([]byte(name)),
		encodeKey: func(value string) ([]byte, error) {
			return []byte(value), nil
		},
		decodeKey: func(encoded []byte) (string, error) {
			return string(encoded), nil
		},
		encodeValue: func(value string) ([]byte, error) {
			return []byte(value), nil
		},
		decodeValue: func(encoded []byte) (string, error) {
			return string(encoded), nil
		},
	}
}

func (c *controllableCodec) CompatibilityID() Digest { return c.id }
func (c *controllableCodec) EncodeKey(value string) ([]byte, error) {
	return c.encodeKey(value)
}
func (c *controllableCodec) DecodeKey(encoded []byte) (string, error) {
	return c.decodeKey(encoded)
}
func (c *controllableCodec) EncodeValue(value string) ([]byte, error) {
	return c.encodeValue(value)
}
func (c *controllableCodec) DecodeValue(encoded []byte) (string, error) {
	return c.decodeValue(encoded)
}

func TestConfigurationAndCodecFailures(t *testing.T) {
	t.Parallel()

	var nilCodec *controllableCodec
	if _, err := New[string, string](nilCodec); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("typed nil codec error = %v", err)
	}
	codec := newControllableCodec("configuration-errors/v1")
	if _, err := New[string, string](codec, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("nil option error = %v", err)
	}
	if _, err := New[string, string](codec, WithNamespace(make([]byte, MaximumKeyBytes+1))); !errors.Is(err, ErrBound) {
		t.Fatalf("oversized namespace error = %v", err)
	}
	tree, err := New[string, string](codec)
	if err != nil {
		t.Fatal(err)
	}
	if tree.CompatibilityID() != codec.id || tree.FormatID() == (Digest{}) {
		t.Fatal("tree did not expose its codec and format identities")
	}

	encodeKeyError := errors.New("encode key")
	codec.encodeKey = func(string) ([]byte, error) { return nil, encodeKeyError }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, encodeKeyError) {
		t.Fatalf("key encoding error = %v", err)
	}
	if _, _, err := tree.Lookup("key"); !errors.Is(err, encodeKeyError) {
		t.Fatalf("lookup key encoding error = %v", err)
	}
	if _, _, err := tree.Delete("key"); !errors.Is(err, encodeKeyError) {
		t.Fatalf("delete key encoding error = %v", err)
	}

	codec = newControllableCodec("key-decode-errors/v1")
	tree, _ = New[string, string](codec)
	decodeKeyError := errors.New("decode key")
	codec.decodeKey = func([]byte) (string, error) { return "", decodeKeyError }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("key decoding error = %v", err)
	}

	codec = newControllableCodec("key-canonical-errors/v1")
	tree, _ = New[string, string](codec)
	codec.decodeKey = func([]byte) (string, error) { return "different", nil }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("non-canonical key error = %v", err)
	}

	codec = newControllableCodec("value-errors/v1")
	tree, _ = New[string, string](codec)
	encodeValueError := errors.New("encode value")
	codec.encodeValue = func(string) ([]byte, error) { return nil, encodeValueError }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, encodeValueError) {
		t.Fatalf("value encoding error = %v", err)
	}
	codec.encodeValue = func(string) ([]byte, error) { return make([]byte, MaximumValueBytes+1), nil }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, ErrBound) {
		t.Fatalf("oversized value error = %v", err)
	}
	codec.encodeValue = func(value string) ([]byte, error) { return []byte(value), nil }
	decodeValueError := errors.New("decode value")
	codec.decodeValue = func([]byte) (string, error) { return "", decodeValueError }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("value decoding error = %v", err)
	}
	codec.decodeValue = func([]byte) (string, error) { return "different", nil }
	if _, _, err := tree.Put("key", "value"); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("non-canonical value error = %v", err)
	}
}

func TestEntriesEmptyInternalAndCodecFailures(t *testing.T) {
	t.Parallel()
	codec := newControllableCodec("entries-errors/v1")
	tree, _ := New[string, string](codec)
	for range tree.Entries() {
		t.Fatal("empty tree yielded an entry")
	}
	for i := range MaximumLeafEntries + 1 {
		var err error
		tree, _, err = tree.Put(fmt.Sprintf("key-%03d", i), "value")
		if err != nil {
			t.Fatal(err)
		}
	}
	count := 0
	for _, err := range tree.Entries() {
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != MaximumLeafEntries+1 {
		t.Fatalf("entry count = %d", count)
	}

	var zero Tree[string, string]
	for _, err := range zero.Entries() {
		if !errors.Is(err, ErrCorrupt) {
			t.Fatalf("zero tree error = %v", err)
		}
	}

	decodeError := errors.New("codec changed")
	codec.decodeKey = func([]byte) (string, error) { return "", decodeError }
	for _, err := range tree.Entries() {
		if !errors.Is(err, decodeError) {
			t.Fatalf("entry key error = %v", err)
		}
		break
	}
	codec.decodeKey = func(encoded []byte) (string, error) { return string(encoded), nil }
	codec.decodeValue = func([]byte) (string, error) { return "", decodeError }
	for _, err := range tree.Entries() {
		if !errors.Is(err, decodeError) {
			t.Fatalf("entry value error = %v", err)
		}
		break
	}
}

func TestLoadAndOpenRejectInvalidInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec := newStringCodec("load-input-errors/v1")
	empty, _ := New[string, uint64](codec)
	loaded, err := Load[string, uint64](ctx, codec, empty.Root(), nil)
	if err != nil || loaded.Root() != empty.Root() {
		t.Fatalf("load empty: root=%v err=%v", loaded.Root(), err)
	}
	if _, err := Load[string, uint64](ctx, codec, emptyReference(Digest{1}), nil); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("mismatched empty root error = %v", err)
	}
	invalidReferences := []Reference{
		{Kind: Kind(99), ID: Digest{1}, Semantic: SemanticRoot{Count: 1}},
		{Kind: KindLeaf, Semantic: SemanticRoot{Count: 1}},
		{Kind: KindLeaf, ID: Digest{1}},
		{Kind: KindLeaf, ID: Digest{1}, Semantic: SemanticRoot{Count: MaximumLeafEntries + 1}},
	}
	if _, err := Load[string, uint64](ctx, codec, Reference{}, nil); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("zero root load error = %v", err)
	}
	if _, err := Open[string, uint64](codec, Reference{}, nil); !errors.Is(err, ErrInvalidRoot) {
		t.Fatalf("zero root open error = %v", err)
	}
	for _, ref := range invalidReferences {
		if _, err := Load[string, uint64](ctx, codec, ref, nil); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Load(%+v) error = %v", ref, err)
		}
		if _, err := Open[string, uint64](codec, ref, nil); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open(%+v) error = %v", ref, err)
		}
	}

	populated, _, _ := empty.Put("key", 1)
	if _, err := Load[string, uint64](ctx, codec, populated.Root(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil load resolver error = %v", err)
	}
	if _, err := Open[string, uint64](codec, populated.Root(), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("nil snapshot resolver error = %v", err)
	}
	resolverError := errors.New("storage unavailable")
	failingResolver := ResolverFunc(func(context.Context, Reference) ([]byte, error) {
		return nil, resolverError
	})
	if _, err := Load(ctx, codec, populated.Root(), failingResolver); !errors.Is(err, resolverError) {
		t.Fatalf("resolver error = %v", err)
	}
	if _, err := Load(ctx, codec, populated.Root(), ResolverFunc(func(context.Context, Reference) ([]byte, error) {
		return []byte("bad object"), nil
	})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt resolved object error = %v", err)
	}

	snapshot, err := Open[string, uint64](codec, empty.Root(), failingResolver)
	if err != nil || snapshot.FormatID() != empty.FormatID() {
		t.Fatalf("open empty snapshot: format=%x err=%v", snapshot.FormatID(), err)
	}
	if _, found, err := snapshot.Lookup(ctx, "missing"); err != nil || found {
		t.Fatalf("empty lookup: found=%v err=%v", found, err)
	}
	if _, changed, err := snapshot.Delete(ctx, "missing"); err != nil || changed {
		t.Fatalf("empty delete: changed=%v err=%v", changed, err)
	}
}

func TestSnapshotPropagatesCodecAndResolverFailures(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec := newControllableCodec("snapshot-errors/v1")
	tree, _ := New[string, string](codec)
	tree, _, _ = tree.Put("key", "value")
	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	snapshot, err := Open[string, string](codec, tree.Root(), mapResolverForTest(stored))
	if err != nil {
		t.Fatal(err)
	}
	unchanged, changed, err := snapshot.Put(ctx, "key", "value")
	if err != nil || changed || unchanged.Root() != snapshot.Root() {
		t.Fatalf("identical put: changed=%v err=%v", changed, err)
	}
	unchanged, changed, err = snapshot.Delete(ctx, "missing")
	if err != nil || changed || unchanged.Root() != snapshot.Root() {
		t.Fatalf("missing delete: changed=%v err=%v", changed, err)
	}
	if change := snapshot.FinalChange(); change.Root != change.Base || len(change.Objects) != 0 {
		t.Fatalf("unchanged final change = %+v", change)
	}

	codecError := errors.New("codec unavailable")
	codec.encodeKey = func(string) ([]byte, error) { return nil, codecError }
	if _, _, err := snapshot.Lookup(ctx, "key"); !errors.Is(err, codecError) {
		t.Fatalf("lookup codec error = %v", err)
	}
	if _, _, err := snapshot.Put(ctx, "key", "value"); !errors.Is(err, codecError) {
		t.Fatalf("put codec error = %v", err)
	}
	if _, _, err := snapshot.Delete(ctx, "key"); !errors.Is(err, codecError) {
		t.Fatalf("delete codec error = %v", err)
	}
	codec.encodeKey = func(value string) ([]byte, error) { return []byte(value), nil }
	codec.encodeValue = func(string) ([]byte, error) { return nil, codecError }
	if _, _, err := snapshot.Put(ctx, "key", "value"); !errors.Is(err, codecError) {
		t.Fatalf("put value codec error = %v", err)
	}

	failing, _ := Open[string, string](codec, tree.Root(), ResolverFunc(func(context.Context, Reference) ([]byte, error) {
		return nil, ErrNotFound
	}))
	codec.encodeValue = func(value string) ([]byte, error) { return []byte(value), nil }
	if _, _, err := failing.Lookup(ctx, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookup resolver error = %v", err)
	}
	if _, _, err := failing.Put(ctx, "key", "new"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("put resolver error = %v", err)
	}
	if _, _, err := failing.Delete(ctx, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete resolver error = %v", err)
	}
}

func TestSnapshotChildEditing(t *testing.T) {
	t.Parallel()
	first := Reference{Kind: KindLeaf, ID: Digest{1}, Semantic: SemanticRoot{Count: 1}}
	second := Reference{Kind: KindLeaf, ID: Digest{2}, Semantic: SemanticRoot{Count: 1}}
	children := setChild(nil, 4, first)
	children = setChild(children, 2, second)
	if len(children) != 2 || children[0].Slot != 2 || childAt(children, 4) != first {
		t.Fatalf("inserted children = %+v", children)
	}
	children = setChild(children, 4, second)
	if childAt(children, 4) != second {
		t.Fatal("existing child was not replaced")
	}
	before := slices.Clone(children)
	children = setChild(children, 3, Reference{})
	if !slices.Equal(children, before) {
		t.Fatal("removing an absent child changed the slice")
	}
	children = setChild(children, 2, Reference{})
	if len(children) != 1 || childAt(children, 2) != (Reference{}) {
		t.Fatalf("child was not removed: %+v", children)
	}
}

func TestInternalBoundsAndRoutingHelpers(t *testing.T) {
	t.Parallel()
	format := Digest{1}
	if _, err := buildLeaf(format, 0, nil); !errors.Is(err, ErrBound) {
		t.Fatalf("empty leaf error = %v", err)
	}
	if _, err := leafDocument(format, 0, nil); !errors.Is(err, ErrBound) {
		t.Fatalf("empty leaf document error = %v", err)
	}
	if _, _, err := subtreeDocuments(format, MaximumDepth, make([]entry, MaximumLeafEntries+1)); !errors.Is(err, ErrCollision) {
		t.Fatalf("exhausted routing error = %v", err)
	}
	if _, err := buildNode(format, MaximumDepth, [fanout]*object{}); !errors.Is(err, ErrBound) {
		t.Fatalf("deep node error = %v", err)
	}
	if _, err := buildNode(format, 0, [fanout]*object{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty node error = %v", err)
	}
	var wrongDepth [fanout]*object
	wrongDepth[0] = &object{depth: 2, semantic: SemanticRoot{Count: 1}}
	if _, err := buildNode(format, 0, wrongDepth); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("child depth error = %v", err)
	}
	var overflow [fanout]*object
	overflow[0] = &object{depth: 1, semantic: SemanticRoot{Count: math.MaxUint64}}
	overflow[1] = &object{depth: 1, semantic: SemanticRoot{Count: 1}}
	if _, err := buildNode(format, 0, overflow); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("summary overflow error = %v", err)
	}

	var digest Digest
	setDigestNibble(&digest, 0, 0xa)
	setDigestNibble(&digest, 1, 0xb)
	if digest[0] != 0xab || !digestPrefixMatches(digest, Digest{0xab}, 2) || digestPrefixMatches(digest, Digest{0xac}, 2) {
		t.Fatalf("nibble routing produced %x", digest[0])
	}
	if _, _, err := readCanonicalUvarint([]byte{0x80, 0}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("non-canonical varint error = %v", err)
	}
}

func TestDecodeObjectRejectsMalformedLeafFields(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("malformed-leaves/v1")
	tree, _ := New[string, uint64](codec)
	tree, _, _ = tree.Put("key", 42)
	payload := tree.Objects()[0].Payload
	assertCorrupt := func(name string, invalid []byte) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObject[string, uint64](codec, invalid, Digest{}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := DecodeObject[string, uint64](nil, payload, Digest{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("nil codec error = %v", err)
	}
	if _, err := DecodeObject[string, uint64](codec, payload, Digest{}, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("nil decoder option error = %v", err)
	}
	assertCorrupt("truncated object", payload[:7])
	assertCorrupt("oversized object", make([]byte, MaximumLeafBytes+1))
	assertCorrupt("short leaf", appendObjectHeader(nil, KindLeaf))

	mutate := func(index int, value byte) []byte {
		invalid := slices.Clone(payload)
		invalid[index] = value
		return invalid
	}
	assertCorrupt("format", mutate(8, payload[8]^1))
	assertCorrupt("depth", mutate(40, MaximumDepth+1))
	assertCorrupt("zero count", mutate(42, 0))
	semanticCount := slices.Clone(payload)
	binary.BigEndian.PutUint64(semanticCount[43:51], 2)
	assertCorrupt("semantic count", semanticCount)
	assertCorrupt("invalid key varint", mutate(83, 0x80))
	truncatedKey := slices.Clone(payload[:84])
	truncatedKey[83] = 10
	assertCorrupt("truncated key", truncatedKey)
	valueLengthOffset := 83 + 1 + len("key")
	assertCorrupt("invalid value varint", mutate(valueLengthOffset, 0x80))
	truncatedValue := slices.Clone(payload[:valueLengthOffset+1])
	truncatedValue[valueLengthOffset] = 8
	assertCorrupt("truncated value", truncatedValue)
	assertCorrupt("semantic fingerprint", mutate(51, payload[51]^1))

	oversizedKey := slices.Clone(payload[:leafHeaderBytes])
	oversizedKey = binary.AppendUvarint(oversizedKey, MaximumKeyBytes+1)
	assertCorrupt("oversized key", oversizedKey)
	oversizedValue := slices.Clone(payload[:leafHeaderBytes])
	oversizedValue = binary.AppendUvarint(oversizedValue, 0)
	oversizedValue = binary.AppendUvarint(oversizedValue, MaximumValueBytes+1)
	assertCorrupt("oversized value", oversizedValue)
}

func TestLookupMissingKeysAndChangedCodec(t *testing.T) {
	t.Parallel()
	codec := newControllableCodec("lookup-paths/v1")
	tree, _ := New[string, string](codec)
	if _, found, err := tree.Lookup("missing"); err != nil || found {
		t.Fatalf("empty lookup: found=%v err=%v", found, err)
	}
	tree, _, _ = tree.Put("present", "value")
	if _, found, err := tree.Lookup("missing"); err != nil || found {
		t.Fatalf("leaf miss: found=%v err=%v", found, err)
	}
	decodeError := errors.New("decoder changed")
	codec.decodeValue = func([]byte) (string, error) { return "", decodeError }
	if _, found, err := tree.Lookup("present"); !errors.Is(err, decodeError) || found {
		t.Fatalf("changed decoder lookup: found=%v err=%v", found, err)
	}
}

func TestValidateCanonicalReportsCodecFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*controllableCodec)
	}{
		{"decode key", func(codec *controllableCodec) {
			codec.decodeKey = func([]byte) (string, error) { return "", errors.New("decode key") }
		}},
		{"reencode key", func(codec *controllableCodec) {
			codec.encodeKey = func(string) ([]byte, error) { return nil, errors.New("encode key") }
		}},
		{"decode value", func(codec *controllableCodec) {
			codec.decodeValue = func([]byte) (string, error) { return "", errors.New("decode value") }
		}},
		{"reencode value", func(codec *controllableCodec) {
			codec.encodeValue = func(string) ([]byte, error) { return nil, errors.New("encode value") }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			codec := newControllableCodec("validate-canonical/" + test.name)
			test.change(codec)
			if err := validateCanonical[string, string](codec, []byte("key"), []byte("value")); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestLoadObjectValidationPaths(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec := newStringCodec("load-object-validation/v1")
	tree, _ := New[string, uint64](codec)
	format := tree.FormatID()
	routeEntry := newEntry(format, []byte("key"), binary.BigEndian.AppendUint64(nil, 1))
	leaf, err := buildLeaf(format, 1, []entry{routeEntry})
	if err != nil {
		t.Fatal(err)
	}
	ref := objectReference(leaf)
	resolver := ResolverFunc(func(context.Context, Reference) ([]byte, error) {
		return slices.Clone(leaf.encoded), nil
	})
	if _, err := loadObject(ctx, codec, format, ref, 1, routeEntry.keyDigest, resolver, map[Digest]struct{}{ref.ID: {}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("repeated reference error = %v", err)
	}
	mismatch := ref
	mismatch.Semantic.Count++
	if _, err := loadObject(ctx, codec, format, mismatch, 1, routeEntry.keyDigest, resolver, make(map[Digest]struct{})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("reference mismatch error = %v", err)
	}
	prefix := routeEntry.keyDigest
	setDigestNibble(&prefix, 0, digestNibble(prefix, 0)^1)
	if _, err := loadObject(ctx, codec, format, ref, 1, prefix, resolver, make(map[Digest]struct{})); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("prefix mismatch error = %v", err)
	}

	populated, _ := New[string, uint64](codec)
	for i := range MaximumLeafEntries + 1 {
		populated, _, _ = populated.Put(fmt.Sprintf("key-%03d", i), uint64(i))
	}
	rootPayload := populated.root.encoded
	childError := errors.New("child unavailable")
	resolver = ResolverFunc(func(_ context.Context, requested Reference) ([]byte, error) {
		if requested.ID == populated.Root().ID {
			return slices.Clone(rootPayload), nil
		}
		return nil, childError
	})
	if _, err := Load(ctx, codec, populated.Root(), resolver); !errors.Is(err, childError) {
		t.Fatalf("child resolver error = %v", err)
	}
	if _, err := Load[string, uint64](ctx, nil, populated.Root(), resolver); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("invalid load codec error = %v", err)
	}
}

func TestObjectsDeduplicatesSharedObjects(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("shared-objects/v1")
	tree, _ := New[string, uint64](codec)
	tree, _, _ = tree.Put("key", 1)
	leaf, err := buildLeaf(tree.format, 1, tree.root.leaf)
	if err != nil {
		t.Fatal(err)
	}
	var children [fanout]*object
	children[0], children[1] = leaf, leaf
	root, err := buildNode(tree.format, 0, children)
	if err != nil {
		t.Fatal(err)
	}
	tree.root = root
	objects := tree.Objects()
	if len(objects) != 2 || objects[0].ID != leaf.content || objects[1].ID != root.content {
		t.Fatalf("objects = %+v", objects)
	}
}

func TestSnapshotMissingPathsAndLastDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec := newStringCodec("snapshot-missing/v1")
	tree, _ := New[string, uint64](codec)
	tree, _, _ = tree.Put("present", 1)
	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	snapshot, _ := Open[string, uint64](codec, tree.Root(), mapResolverForTest(stored))
	if _, found, err := snapshot.Lookup(ctx, "missing"); err != nil || found {
		t.Fatalf("leaf miss: found=%v err=%v", found, err)
	}
	empty, changed, err := snapshot.Delete(ctx, "present")
	if err != nil || !changed || empty.Root().Kind != KindEmpty {
		t.Fatalf("last delete: root=%+v changed=%v err=%v", empty.Root(), changed, err)
	}
}

func TestSnapshotValidationHelpers(t *testing.T) {
	t.Parallel()
	format := Digest{1}
	document := EncodedObject{Format: format, Kind: KindLeaf, ID: Digest{2}, Depth: 1, Semantic: SemanticRoot{Count: 1}}
	ref := documentReference(document)
	if _, err := validateResolved(document, format, ref, 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("resolved depth mismatch error = %v", err)
	}
	routeEntry := newEntry(format, []byte("key"), []byte("value"))
	prefix := routeEntry.keyDigest
	setDigestNibble(&prefix, 0, digestNibble(prefix, 0)^1)
	if err := validateLeafPrefix([]entry{routeEntry}, prefix, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("leaf prefix error = %v", err)
	}
	if _, err := nodeDocument(format, 0, []ChildReference{{Slot: 0}}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("invalid child reference error = %v", err)
	}
	if _, err := nodeDocument(format, 0, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("empty node document error = %v", err)
	}
}

func TestInternalPathMissesAndLastDeletion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec := newStringCodec("sparse-internal-paths/v1")
	tree, _ := New[string, uint64](codec)
	format := tree.FormatID()
	keys := make([]string, 0, MaximumLeafEntries+1)
	occupiedSlot := -1
	missingKey := ""
	for candidate := 0; len(keys) < MaximumLeafEntries+1 || missingKey == ""; candidate++ {
		key := fmt.Sprintf("candidate-%05d", candidate)
		slot := digestNibble(keyDigest(format, []byte(key)), 0)
		if occupiedSlot == -1 {
			occupiedSlot = slot
		}
		if slot == occupiedSlot && len(keys) < MaximumLeafEntries+1 {
			keys = append(keys, key)
		} else if slot != occupiedSlot && missingKey == "" {
			missingKey = key
		}
	}
	for i, key := range keys {
		tree, _, _ = tree.Put(key, uint64(i))
	}
	if tree.Height() == 0 {
		t.Fatal("test fixture did not create an internal node")
	}
	if _, found, err := tree.Lookup(missingKey); err != nil || found {
		t.Fatalf("tree internal miss: found=%v err=%v", found, err)
	}
	if unchanged, changed, err := tree.Put(keys[0], 0); err != nil || changed || unchanged.Root() != tree.Root() {
		t.Fatalf("tree internal identical put: changed=%v err=%v", changed, err)
	}
	if unchanged, changed, err := tree.Delete(missingKey); err != nil || changed || unchanged.Root() != tree.Root() {
		t.Fatalf("tree internal missing delete: changed=%v err=%v", changed, err)
	}

	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	snapshot, err := Open[string, uint64](codec, tree.Root(), mapResolverForTest(stored))
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := snapshot.Lookup(ctx, missingKey); err != nil || found {
		t.Fatalf("snapshot internal miss: found=%v err=%v", found, err)
	}
	if _, changed, err := snapshot.Put(ctx, keys[0], 0); err != nil || changed {
		t.Fatalf("snapshot internal identical put: changed=%v err=%v", changed, err)
	}
	if _, changed, err := snapshot.Delete(ctx, missingKey); err != nil || changed {
		t.Fatalf("snapshot internal missing delete: changed=%v err=%v", changed, err)
	}

	for _, key := range keys {
		var changed bool
		tree, changed, err = tree.Delete(key)
		if err != nil || !changed {
			t.Fatalf("tree delete %q: changed=%v err=%v", key, changed, err)
		}
		snapshot, changed, err = snapshot.Delete(ctx, key)
		if err != nil || !changed {
			t.Fatalf("snapshot delete %q: changed=%v err=%v", key, changed, err)
		}
	}
	if tree.Root().Kind != KindEmpty || snapshot.Root().Kind != KindEmpty {
		t.Fatalf("last deletion roots: tree=%+v snapshot=%+v", tree.Root(), snapshot.Root())
	}
}

func TestDecodeObjectRejectsChangedCodec(t *testing.T) {
	t.Parallel()
	codec := newControllableCodec("changed-codec/v1")
	tree, _ := New[string, string](codec)
	tree, _, _ = tree.Put("key", "value")
	payload := tree.Objects()[0].Payload
	codec.decodeKey = func([]byte) (string, error) { return "", errors.New("key decoder changed") }
	if _, err := DecodeObject[string, string](codec, payload, Digest{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("changed codec error = %v", err)
	}
	if _, err := Open[string, string](nil, tree.Root(), nil); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("invalid snapshot codec error = %v", err)
	}
}

func TestDecodeObjectRejectsMalformedNodeFields(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("malformed-nodes/v1")
	tree, _ := New[string, uint64](codec)
	for i := range MaximumLeafEntries + 1 {
		tree, _, _ = tree.Put(fmt.Sprintf("key-%03d", i), uint64(i))
	}
	payload := tree.Objects()[len(tree.Objects())-1].Payload
	if Kind(payload[5]) != KindNode {
		t.Fatal("test fixture is not a node")
	}
	assertCorrupt := func(name string, invalid []byte) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeObject[string, uint64](codec, invalid, Digest{}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	mutate := func(index int, value byte) []byte {
		invalid := slices.Clone(payload)
		invalid[index] = value
		return invalid
	}
	assertCorrupt("short node", appendObjectHeader(nil, KindNode))
	assertCorrupt("format", mutate(8, payload[8]^1))
	assertCorrupt("depth", mutate(40, MaximumDepth))
	assertCorrupt("stride", mutate(41, strideBits+1))
	zeroSemantic := slices.Clone(payload)
	binary.BigEndian.PutUint64(zeroSemantic[42:50], 0)
	assertCorrupt("zero semantic", zeroSemantic)
	assertCorrupt("zero children", mutate(82, 0))
	assertCorrupt("truncated", payload[:len(payload)-1])
	assertCorrupt("invalid slot", mutate(nodeHeaderBytes, fanout))
	assertCorrupt("invalid kind", mutate(nodeHeaderBytes+1, byte(KindEmpty)))
	zeroChildCount := slices.Clone(payload)
	binary.BigEndian.PutUint64(zeroChildCount[nodeHeaderBytes+2:nodeHeaderBytes+10], 0)
	assertCorrupt("zero child count", zeroChildCount)
	zeroChildID := slices.Clone(payload)
	childIDOffset := nodeHeaderBytes + 2 + 8 + sha256.Size
	clear(zeroChildID[childIDOffset : childIDOffset+sha256.Size])
	assertCorrupt("zero child id", zeroChildID)
	assertCorrupt("semantic mismatch", mutate(50, payload[50]^1))

	if payload[82] >= 2 {
		duplicateSlot := slices.Clone(payload)
		duplicateSlot[nodeHeaderBytes+childBytes] = duplicateSlot[nodeHeaderBytes]
		assertCorrupt("duplicate slot", duplicateSlot)
	}
}
