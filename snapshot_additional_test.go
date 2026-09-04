package merkletrie

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
)

func TestSnapshotMutationsMatchTreeAndReopen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := Open[string, uint64](codec, tree.Root(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaximumLeafEntries + 25 {
		key := fmt.Sprintf("key-%04d", i)
		tree, _, err = tree.Put(key, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		snapshot, _, err = snapshot.Put(ctx, key, uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Root() != tree.Root() {
			t.Fatalf("root mismatch after put %d", i)
		}
	}
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("key-%04d", i)
		tree, _, err = tree.Delete(key)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, _, err = snapshot.Delete(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Root() != tree.Root() {
			t.Fatalf("root mismatch after delete %d", i)
		}
	}

	change := snapshot.FinalChange()
	stored := make(map[Digest][]byte, len(change.Objects))
	positions := make(map[Digest]int, len(change.Objects))
	for i, object := range change.Objects {
		for _, child := range object.Children {
			if position, created := positions[child.Reference.ID]; created && position >= i {
				t.Fatal("parent appeared before a newly staged child")
			}
		}
		positions[object.ID] = i
		stored[object.ID] = slices.Clone(object.Payload)
	}
	resolver := mapResolverForTest(stored)
	loaded, err := Load(ctx, codec, change.Root, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Root() != tree.Root() {
		t.Fatal("loaded root mismatch")
	}
}

func TestSnapshotConcurrentBranchesRemainIndependent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := New[string, uint64](codec)
	for i := range 1_000 {
		tree, _, err = tree.Put(fmt.Sprintf("key-%04d", i), 1)
		if err != nil {
			t.Fatal(err)
		}
	}
	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	base, err := Open[string, uint64](codec, tree.Root(), mapResolverForTest(stored))
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		key      string
		snapshot Snapshot[string, uint64]
		err      error
	}
	results := make(chan result, 2)
	var start sync.WaitGroup
	start.Add(1)
	mutate := func(key string) {
		start.Wait()
		branch, _, branchErr := base.Put(ctx, key, 2)
		results <- result{key: key, snapshot: branch, err: branchErr}
	}
	go mutate("key-0100")
	go mutate("key-0900")
	start.Done()
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		value, found, lookupErr := result.snapshot.Lookup(ctx, result.key)
		if lookupErr != nil || !found || value != 2 {
			t.Fatalf("key=%s value=%d found=%v err=%v", result.key, value, found, lookupErr)
		}
	}
	for _, key := range []string{"key-0100", "key-0900"} {
		value, found, lookupErr := base.Lookup(ctx, key)
		if lookupErr != nil || !found || value != 1 {
			t.Fatalf("base changed for %s", key)
		}
	}
}

func TestSnapshotRejectsWrongFormatOnResolution(t *testing.T) {
	t.Parallel()
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := New[string, uint64](codec, WithNamespace([]byte("first")))
	tree, _, err = tree.Put("key", 1)
	if err != nil {
		t.Fatal(err)
	}
	object := tree.Objects()[0]
	snapshot, err := Open[string, uint64](codec, tree.Root(), ResolverFunc(func(context.Context, Reference) ([]byte, error) {
		return slices.Clone(object.Payload), nil
	}), WithNamespace([]byte("second")))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = snapshot.Lookup(context.Background(), "key")
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("wrong format error=%v", err)
	}
}

func TestMaximumKeyAndValueFitOneLeaf(t *testing.T) {
	t.Parallel()
	codec, err := NewCodec(BytesEncoding(), BytesEncoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := New[[]byte, []byte](codec)
	tree, changed, err := tree.Put(make([]byte, MaximumKeyBytes), make([]byte, MaximumValueBytes))
	if err != nil || !changed || tree.Len() != 1 {
		t.Fatalf("changed=%v len=%d err=%v", changed, tree.Len(), err)
	}
}

func mapResolverForTest(stored map[Digest][]byte) ResolverFunc {
	return func(_ context.Context, ref Reference) ([]byte, error) {
		payload, ok := stored[ref.ID]
		if !ok {
			return nil, ErrNotFound
		}
		return slices.Clone(payload), nil
	}
}
