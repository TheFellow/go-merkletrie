package merkletrie

import (
	"context"
	"fmt"
	"slices"
	"testing"
)

func BenchmarkPut(b *testing.B) {
	codec := benchmarkCodec(b)
	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("N=%d", size), func(b *testing.B) {
			tree := benchmarkTree(b, codec, size)
			key := fmt.Sprintf("key-%08d", size/2)
			var revision uint64
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				revision++
				var err error
				tree, _, err = tree.Put(key, revision)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLookup(b *testing.B) {
	codec := benchmarkCodec(b)
	for _, size := range []int{1_000, 10_000, 100_000} {
		b.Run(fmt.Sprintf("N=%d", size), func(b *testing.B) {
			tree := benchmarkTree(b, codec, size)
			key := fmt.Sprintf("key-%08d", size/2)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, found, err := tree.Lookup(key); err != nil || !found {
					b.Fatalf("found=%v err=%v", found, err)
				}
			}
		})
	}
}

func BenchmarkSnapshotPut(b *testing.B) {
	codec := benchmarkCodec(b)
	tree := benchmarkTree(b, codec, 100_000)
	stored := make(map[Digest][]byte)
	for _, object := range tree.Objects() {
		stored[object.ID] = slices.Clone(object.Payload)
	}
	resolver := ResolverFunc(func(_ context.Context, ref Reference) ([]byte, error) {
		payload, ok := stored[ref.ID]
		if !ok {
			return nil, ErrNotFound
		}
		return slices.Clone(payload), nil
	})
	key := "key-00050000"
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		snapshot, err := Open(codec, tree.Root(), resolver)
		if err != nil {
			b.Fatal(err)
		}
		if _, changed, err := snapshot.Put(context.Background(), key, uint64(2)); err != nil || !changed {
			b.Fatalf("changed=%v err=%v", changed, err)
		}
	}
}

func benchmarkCodec(b testing.TB) PairCodec[string, uint64] {
	b.Helper()
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		b.Fatal(err)
	}
	return codec
}

func benchmarkTree(b testing.TB, codec PairCodec[string, uint64], size int) Tree[string, uint64] {
	b.Helper()
	tree, err := New[string, uint64](codec)
	if err != nil {
		b.Fatal(err)
	}
	for i := range size {
		tree, _, err = tree.Put(fmt.Sprintf("key-%08d", i), uint64(i))
		if err != nil {
			b.Fatal(err)
		}
	}
	return tree
}
