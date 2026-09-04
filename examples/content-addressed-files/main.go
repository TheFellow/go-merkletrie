// Command content-addressed-files demonstrates a Merkle trie as a versioned
// index over files stored in a content-addressed blob store.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/TheFellow/go-merkletrie"
)

const fileRecordBytes = sha256.Size + 8

type fileRecord struct {
	Blob merkletrie.Digest
	Size uint64
}

// diskStore keeps application blobs and trie objects in separate
// content-addressed directories. Production code would also atomically store
// the currently published root reference.
type diskStore struct {
	directory string
}

func (store diskStore) putBlob(contents []byte) (fileRecord, error) {
	id := sha256.Sum256(contents)
	if err := store.put("blobs", id, contents); err != nil {
		return fileRecord{}, err
	}
	return fileRecord{Blob: id, Size: uint64(len(contents))}, nil
}

func (store diskStore) getBlob(record fileRecord) ([]byte, error) {
	contents, err := os.ReadFile(store.path("blobs", record.Blob))
	if err != nil {
		return nil, err
	}
	if uint64(len(contents)) != record.Size || sha256.Sum256(contents) != record.Blob {
		return nil, fmt.Errorf("blob %x failed verification", record.Blob)
	}
	return contents, nil
}

func (store diskStore) putObjects(objects []merkletrie.EncodedObject) error {
	for _, object := range objects {
		if err := store.put("trie", object.ID, object.Payload); err != nil {
			return err
		}
	}
	return nil
}

// Resolve lets a lazy Snapshot load trie objects from disk as needed.
func (store diskStore) Resolve(_ context.Context, ref merkletrie.Reference) ([]byte, error) {
	payload, err := os.ReadFile(store.path("trie", ref.ID))
	if os.IsNotExist(err) {
		return nil, merkletrie.ErrNotFound
	}
	return payload, err
}

func (store diskStore) put(kind string, id merkletrie.Digest, payload []byte) error {
	directory := filepath.Join(store.directory, kind)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	path := store.path(kind, id)
	existing, err := os.ReadFile(path)
	if err == nil {
		if !bytes.Equal(existing, payload) {
			return fmt.Errorf("content mismatch at %s", path)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func (store diskStore) path(kind string, id merkletrie.Digest) string {
	return filepath.Join(store.directory, kind, hex.EncodeToString(id[:]))
}

func main() {
	ctx := context.Background()
	directory, err := os.MkdirTemp("", "go-merkletrie-files-")
	check(err)
	defer os.RemoveAll(directory)
	store := diskStore{directory: directory}

	fileEncoding, err := merkletrie.NewEncoding(
		sha256.Sum256([]byte("example/file-record/v1")),
		func(record fileRecord) ([]byte, error) {
			encoded := append([]byte(nil), record.Blob[:]...)
			return binary.BigEndian.AppendUint64(encoded, record.Size), nil
		},
		func(encoded []byte) (fileRecord, error) {
			if len(encoded) != fileRecordBytes {
				return fileRecord{}, fmt.Errorf("invalid file record length %d", len(encoded))
			}
			var record fileRecord
			copy(record.Blob[:], encoded[:sha256.Size])
			record.Size = binary.BigEndian.Uint64(encoded[sha256.Size:])
			return record, nil
		},
	)
	check(err)
	codec, err := merkletrie.NewCodec(merkletrie.StringEncoding(), fileEncoding)
	check(err)
	tree, err := merkletrie.New(codec, merkletrie.WithNamespace([]byte("files/v1")))
	check(err)

	readme, err := store.putBlob([]byte("hello from version one\n"))
	check(err)
	todo, err := store.putBlob([]byte("ship the example\n"))
	check(err)
	for path, record := range map[string]fileRecord{
		"docs/readme.txt":   readme,
		"copies/readme.txt": readme, // Same contents reuse the same blob.
		"notes/todo.txt":    todo,
	} {
		tree, _, err = tree.Put(path, record)
		check(err)
	}
	check(store.putObjects(tree.Objects()))
	versionOne := tree.Root()

	// Updating a path stages only the changed trie path and writes one new blob.
	versionOneSnapshot, err := merkletrie.Open(codec, versionOne, store, merkletrie.WithNamespace([]byte("files/v1")))
	check(err)
	updatedReadme, err := store.putBlob([]byte("hello from version two\n"))
	check(err)
	versionTwoSnapshot, changed, err := versionOneSnapshot.Put(ctx, "docs/readme.txt", updatedReadme)
	check(err)
	change := versionTwoSnapshot.FinalChange()
	check(store.putObjects(change.Objects)) // Persist objects before publishing Root.
	versionTwo := change.Root

	oldContents := readFile(ctx, store, codec, versionOne, "docs/readme.txt")
	newContents := readFile(ctx, store, codec, versionTwo, "docs/readme.txt")
	copyContents := readFile(ctx, store, codec, versionTwo, "copies/readme.txt")
	fmt.Printf("changed=%v new trie objects=%d\n", changed, len(change.Objects))
	fmt.Printf("v1: %s", oldContents)
	fmt.Printf("v2: %s", newContents)
	fmt.Printf("unchanged copy: %s", copyContents)
	fmt.Printf("initial paths share blob: %v\n", readme.Blob == fileRecordFor(ctx, versionOneSnapshot, "copies/readme.txt").Blob)
}

func readFile(ctx context.Context, store diskStore, codec merkletrie.PairCodec[string, fileRecord], root merkletrie.Reference, path string) string {
	snapshot, err := merkletrie.Open(codec, root, store, merkletrie.WithNamespace([]byte("files/v1")))
	check(err)
	contents, err := store.getBlob(fileRecordFor(ctx, snapshot, path))
	check(err)
	return string(contents)
}

func fileRecordFor(ctx context.Context, snapshot merkletrie.Snapshot[string, fileRecord], path string) fileRecord {
	record, found, err := snapshot.Lookup(ctx, path)
	check(err)
	if !found {
		log.Fatalf("file %q not found", path)
	}
	return record
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
