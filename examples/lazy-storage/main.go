// Command lazy-storage demonstrates content-addressed persistence and lazy updates.
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/TheFellow/go-merkletrie"
)

type memoryStore map[merkletrie.Digest][]byte

func (store memoryStore) Resolve(_ context.Context, ref merkletrie.Reference) ([]byte, error) {
	payload, ok := store[ref.ID]
	if !ok {
		return nil, merkletrie.ErrNotFound
	}
	return append([]byte(nil), payload...), nil
}

func (store memoryStore) put(objects []merkletrie.EncodedObject) {
	for _, object := range objects {
		store[object.ID] = append([]byte(nil), object.Payload...)
	}
}

func main() {
	ctx := context.Background()
	codec, err := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.StringEncoding())
	if err != nil {
		log.Fatal(err)
	}

	// Build and persist an initial generation.
	tree, err := merkletrie.New(codec)
	if err != nil {
		log.Fatal(err)
	}
	for i := range 300 {
		tree, _, err = tree.Put(fmt.Sprintf("key-%03d", i), fmt.Sprintf("value-%03d", i))
		if err != nil {
			log.Fatal(err)
		}
	}
	store := make(memoryStore)
	store.put(tree.Objects())    // objects first
	publishedRoot := tree.Root() // then atomically publish this small reference

	// Open does not load the full tree. Lookups and mutations resolve only the
	// paths they touch and stage new content-addressed objects in memory.
	snapshot, err := merkletrie.Open(codec, publishedRoot, store)
	if err != nil {
		log.Fatal(err)
	}
	value, found, err := snapshot.Lookup(ctx, "key-149")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("lookup: found=%v value=%s\n", found, value)

	snapshot, _, err = snapshot.Put(ctx, "key-149", "updated")
	if err != nil {
		log.Fatal(err)
	}
	snapshot, _, err = snapshot.Put(ctx, "key-300", "new")
	if err != nil {
		log.Fatal(err)
	}
	change := snapshot.FinalChange()

	// FinalChange is children-before-parent. Persist every object successfully
	// before replacing the published root.
	store.put(change.Objects)
	publishedRoot = change.Root

	reopened, err := merkletrie.Open(codec, publishedRoot, store)
	if err != nil {
		log.Fatal(err)
	}
	value, found, err = reopened.Lookup(ctx, "key-149")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("reopened: found=%v value=%s new objects=%d\n", found, value, len(change.Objects))
}
