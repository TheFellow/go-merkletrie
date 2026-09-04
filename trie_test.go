package merkletrie

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
)

type stringCodec struct{ id Digest }

func newStringCodec(name string) stringCodec           { return stringCodec{id: sha256.Sum256([]byte(name))} }
func (c stringCodec) CompatibilityID() Digest          { return c.id }
func (stringCodec) EncodeKey(v string) ([]byte, error) { return []byte(v), nil }
func (stringCodec) DecodeKey(v []byte) (string, error) {
	return string(v), nil
}
func (stringCodec) EncodeValue(v uint64) ([]byte, error) {
	return binary.BigEndian.AppendUint64(nil, v), nil
}
func (stringCodec) DecodeValue(v []byte) (uint64, error) {
	if len(v) != 8 {
		return 0, errors.New("invalid integer")
	}
	return binary.BigEndian.Uint64(v), nil
}

func TestTreeImmutableRandomOperations(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("random/v1")
	tree, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	want := make(map[string]uint64)
	rng := rand.New(rand.NewPCG(7, 19))
	for step := range 2_000 {
		key := "key-" + strconv.Itoa(rng.IntN(300))
		before, beforeWant := tree, cloneMap(want)
		if rng.IntN(4) == 0 {
			var changed bool
			tree, changed, err = tree.Delete(key)
			_, existed := want[key]
			if err != nil || changed != existed {
				t.Fatalf("delete: changed=%v existed=%v err=%v", changed, existed, err)
			}
			delete(want, key)
		} else {
			value := uint64(step + 1)
			tree, _, err = tree.Put(key, value)
			if err != nil {
				t.Fatal(err)
			}
			want[key] = value
		}
		assertTree(t, before, beforeWant)
		assertTree(t, tree, want)
	}
}

func TestTreeSplitsAndIsOrderIndependent(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("split/v1")
	forward, _ := New[string, uint64](codec)
	reverse, _ := New[string, uint64](codec)
	for i := range MaximumLeafEntries + 1 {
		var err error
		forward, _, err = forward.Put(fmt.Sprintf("key-%04d", i), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := MaximumLeafEntries; i >= 0; i-- {
		reverse, _, _ = reverse.Put(fmt.Sprintf("key-%04d", i), uint64(i))
	}
	if forward.Height() == 0 || forward.Root() != reverse.Root() {
		t.Fatalf("split/order mismatch: heights %d/%d", forward.Height(), reverse.Height())
	}
	if forward.Len() != MaximumLeafEntries+1 {
		t.Fatalf("len=%d", forward.Len())
	}
}

func TestPutDeleteAndDetachedCodecBytes(t *testing.T) {
	t.Parallel()
	type mutableCodec struct{ stringCodec }
	codec := mutableCodec{newStringCodec("detached/v1")}
	tree, _ := New[string, uint64](codec)
	one, changed, err := tree.Put("one", 1)
	if err != nil || !changed || tree.Len() != 0 {
		t.Fatalf("put failed: %v %v", changed, err)
	}
	unchanged, changed, err := one.Put("one", 1)
	if err != nil || changed || unchanged.Root() != one.Root() {
		t.Fatal("identical put changed root")
	}
	two, changed, _ := one.Put("one", 2)
	if !changed {
		t.Fatal("replacement unchanged")
	}
	got, found, _ := one.Lookup("one")
	if !found || got != 1 {
		t.Fatalf("old root mutated: %v %d", found, got)
	}
	empty, changed, err := two.Delete("one")
	if err != nil || !changed || empty.Root() != tree.Root() {
		t.Fatalf("delete failed: %v %v", changed, err)
	}
}

func TestObjectsDecodeAndLoad(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("objects/v1")
	tree, _ := New[string, uint64](codec)
	for i := range 500 {
		tree, _, _ = tree.Put(fmt.Sprintf("key-%04d", i), uint64(i*i))
	}
	objects := tree.Objects()
	if len(objects) < 2 {
		t.Fatal("expected internal objects")
	}
	stored := make(map[Digest][]byte, len(objects))
	seen := make(map[Digest]bool)
	for _, object := range objects {
		for _, child := range object.Children {
			if !seen[child.Reference.ID] {
				t.Fatal("objects are not children-first")
			}
		}
		decoded, err := DecodeObject[string, uint64](codec, object.Payload, object.ID)
		if err != nil || decoded.ID != object.ID || decoded.Kind != object.Kind {
			t.Fatalf("decode: %#v %v", decoded, err)
		}
		seen[object.ID] = true
		stored[object.ID] = slices.Clone(object.Payload)
	}
	loaded, err := Load[string, uint64](context.Background(), codec, tree.Root(), ResolverFunc(func(_ context.Context, ref Reference) ([]byte, error) {
		payload, ok := stored[ref.ID]
		if !ok {
			return nil, ErrNotFound
		}
		return slices.Clone(payload), nil
	}))
	if err != nil || loaded.Root() != tree.Root() {
		t.Fatalf("load: %v", err)
	}
	for i := range 500 {
		got, found, err := loaded.Lookup(fmt.Sprintf("key-%04d", i))
		if err != nil || !found || got != uint64(i*i) {
			t.Fatalf("lookup %d: %d %v %v", i, got, found, err)
		}
	}
}

func TestObjectCodecFailsClosed(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("strict/v1")
	tree, _ := New[string, uint64](codec)
	tree, _, _ = tree.Put("key", 42)
	object := tree.Objects()[0]

	corrupt := slices.Clone(object.Payload)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := DecodeObject[string, uint64](codec, corrupt, object.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption accepted: %v", err)
	}
	trailing := append(slices.Clone(object.Payload), 0)
	if _, err := DecodeObject[string, uint64](codec, trailing, Digest{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("trailing bytes accepted: %v", err)
	}
	other := newStringCodec("strict/v2")
	if _, err := DecodeObject[string, uint64](other, object.Payload, Digest{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong compatibility accepted: %v", err)
	}
	if string(object.Payload[:4]) != "GMTR" || object.Payload[4] != 1 || Kind(object.Payload[5]) != KindLeaf ||
		object.Payload[6] != 0 || object.Payload[7] != 0 {
		t.Fatalf("unexpected object header %x", object.Payload[:8])
	}
	for name, index := range map[string]int{"signature": 0, "version": 4, "kind": 5, "reserved": 6} {
		t.Run(name, func(t *testing.T) {
			invalid := slices.Clone(object.Payload)
			invalid[index] ^= 0xff
			if _, err := DecodeObject[string, uint64](codec, invalid, Digest{}); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("invalid header accepted: %v", err)
			}
		})
	}
}

func TestObjectHeaderCarriesNodeKind(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("node-header/v1")
	tree, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaximumLeafEntries + 1 {
		tree, _, err = tree.Put(fmt.Sprintf("key-%04d", i), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	objects := tree.Objects()
	root := objects[len(objects)-1]
	if root.Kind != KindNode || string(root.Payload[:4]) != "GMTR" || root.Payload[4] != 1 || Kind(root.Payload[5]) != KindNode {
		t.Fatalf("unexpected node header %x", root.Payload[:8])
	}
}

func TestBoundsAndInitialization(t *testing.T) {
	t.Parallel()
	if _, err := New[string, uint64](stringCodec{}); !errors.Is(err, ErrInvalidCodec) {
		t.Fatalf("zero compatibility accepted: %v", err)
	}
	codec := newStringCodec("bounds/v1")
	tree, _ := New[string, uint64](codec)
	if _, _, err := tree.Put("", 1); err != nil {
		t.Fatalf("empty canonical key rejected: %v", err)
	}
	if _, _, err := tree.Put(string(make([]byte, MaximumKeyBytes+1)), 1); !errors.Is(err, ErrBound) {
		t.Fatalf("large key accepted: %v", err)
	}
	var zero Tree[string, uint64]
	if _, _, err := zero.Lookup("key"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("zero tree accepted: %v", err)
	}
}

func TestFormatBindsNamespaceAndEmptyRoot(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("namespace/v1")
	a, _ := New[string, uint64](codec, WithNamespace([]byte("a")))
	b, _ := New[string, uint64](codec, WithNamespace([]byte("b")))
	if a.FormatID() == b.FormatID() || a.Root() == b.Root() {
		t.Fatal("namespace did not separate formats and empty roots")
	}
	a, _, _ = a.Put("key", 1)
	b, _, _ = b.Put("key", 1)
	if a.Root() == b.Root() {
		t.Fatal("namespace did not separate populated roots")
	}
	if _, err := DecodeObject[string, uint64](codec, a.Objects()[0].Payload, Digest{}, WithNamespace([]byte("b"))); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong namespace accepted: %v", err)
	}
}

func TestSemanticRootIgnoresHistoryDependentShape(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("semantic-shape/v1")
	flat, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaximumLeafEntries {
		flat, _, err = flat.Put(fmt.Sprintf("key-%04d", i), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
	}
	shaped, _, err := flat.Put("one-more", 1)
	if err != nil {
		t.Fatal(err)
	}
	shaped, changed, err := shaped.Delete("one-more")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if shaped.Root().Semantic != flat.Root().Semantic {
		t.Fatal("semantic summary depends on physical shape")
	}
	if shaped.Root().ID == flat.Root().ID || shaped.Height() == 0 {
		t.Fatal("delete unexpectedly collapsed physical shape")
	}
}

func TestReturnedObjectsAreDetached(t *testing.T) {
	t.Parallel()
	codec, err := NewCodec(BytesEncoding(), BytesEncoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := New[[]byte, []byte](codec)
	tree, _, err = tree.Put([]byte("key"), []byte("value"))
	if err != nil {
		t.Fatal(err)
	}
	root := tree.Root()
	objects := tree.Objects()
	objects[0].Payload[0] ^= 0xff
	objects[0].Entries[0].Key[0] ^= 0xff
	objects[0].Entries[0].Value[0] ^= 0xff
	value, found, err := tree.Lookup([]byte("key"))
	if err != nil || !found || string(value) != "value" || tree.Root() != root {
		t.Fatalf("value=%q found=%v err=%v", value, found, err)
	}
}

func TestSnapshotResolvesOnlyPath(t *testing.T) {
	t.Parallel()
	codec := newStringCodec("snapshot/v1")
	tree, _ := New[string, uint64](codec)
	for i := range 2_000 {
		tree, _, _ = tree.Put(fmt.Sprintf("key-%08d", i), uint64(i))
	}
	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	reads := 0
	resolver := ResolverFunc(func(_ context.Context, ref Reference) ([]byte, error) {
		reads++
		return slices.Clone(stored[ref.ID]), nil
	})
	snapshot, err := Open[string, uint64](codec, tree.Root(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	got, found, err := snapshot.Lookup(context.Background(), "key-00001000")
	if err != nil || !found || got != 1000 || reads > tree.Height()+1 {
		t.Fatalf("lookup got=%d found=%v reads=%d height=%d err=%v", got, found, reads, tree.Height(), err)
	}
	reads = 0
	next, changed, err := snapshot.Put(context.Background(), "key-00001000", 9999)
	if err != nil || !changed || reads > tree.Height()+1 {
		t.Fatalf("put changed=%v reads=%d err=%v", changed, reads, err)
	}
	change := next.FinalChange()
	if change.Base != tree.Root() || change.Root == change.Base || len(change.Objects) > tree.Height()+1 {
		t.Fatalf("bad change: %#v", change)
	}
	old, _, _ := snapshot.Lookup(context.Background(), "key-00001000")
	updated, _, _ := next.Lookup(context.Background(), "key-00001000")
	if old != 1000 || updated != 9999 {
		t.Fatalf("snapshot immutability: old=%d updated=%d", old, updated)
	}
}

func assertTree(t *testing.T, tree Tree[string, uint64], want map[string]uint64) {
	t.Helper()
	if tree.Len() != uint64(len(want)) {
		t.Fatalf("len=%d want=%d", tree.Len(), len(want))
	}
	for key, value := range want {
		got, found, err := tree.Lookup(key)
		if err != nil || !found || got != value {
			t.Fatalf("lookup %q: got=%d found=%v err=%v", key, got, found, err)
		}
	}
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	result := make(map[K]V, len(source))
	maps.Copy(result, source)
	return result
}
