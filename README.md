# go-merkletrie

`go-merkletrie` is an immutable, generic, content-addressed radix trie for Go.
It gives application-defined keys and values stable Merkle roots, preserves old
versions after updates, and can reopen persisted generations lazily.

The package is deliberately small: SHA-256 routing, a 16-way radix, bounded
canonical objects, and caller-supplied encodings and storage.

## Requirements and installation

The module targets Go 1.27.1.

```sh
go get github.com/TheFellow/go-merkletrie
```

## Quick start

Built-in encodings cover strings, byte slices, and fixed-width integers.
Combine two encodings into a codec, create an empty tree, and retain each
version you care about:

```go
package main

import (
	"fmt"
	"log"

	"github.com/TheFellow/go-merkletrie"
)

func main() {
	codec, err := merkletrie.NewCodec(
		merkletrie.StringEncoding(),
		merkletrie.Uint64Encoding(),
	)
	if err != nil {
		log.Fatal(err)
	}

	empty, err := merkletrie.New(codec)
	if err != nil {
		log.Fatal(err)
	}
	first, changed, err := empty.Put("answer", 42)
	if err != nil {
		log.Fatal(err)
	}

	value, found, err := first.Lookup("answer")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value, found, changed) // 42 true true
	fmt.Println(empty.Len(), first.Len()) // 0 1
}
```

`Put` and `Delete` return a new `Tree`; the receiver is unchanged and remains
safe for concurrent readers. They also report whether the logical value
changed, so a no-op does not create a new root.

## Concepts

### Canonical codecs

A `Codec[K, V]` defines the canonical bytes for keys and values. Those bytes
are the persisted protocol: encoders must be deterministic, and decoders must
reject representations that are not canonical. Change the compatibility ID
whenever the encoding or its meaning changes.

Use `NewEncoding` and `NewCodec` to compose encodings, or implement `Codec`
directly. `WithNamespace` can isolate independent trie formats that otherwise
share a codec. The compatibility ID and namespace must remain stable when
reopening stored data.

### Roots and equality

`Tree.Root()` returns a `Reference` containing the root object's content ID and
a semantic summary. Equal non-empty root IDs prove that the encoded shape and
contents are equal.

Physical roots are history-dependent. In particular, deletion intentionally
does not merge internal nodes, so two trees with the same entries can have
different root IDs. `Reference.Semantic` is shape-independent, but its
`SemanticRoot.Fingerprint` is only an equality hint—not cryptographic proof.
Compare entries through an application-appropriate mechanism when false
equality would matter.

For a materialized tree, `Tree.Entries()` provides a lazy sequence of decoded
key/value pairs. Its order is deterministic but intentionally unspecified.

### Content-addressed persistence

`Tree.Objects()` returns all reachable encoded objects exactly once, ordered
children before parents. A safe generation publish is:

1. Store every object's `Payload` under its `ID`.
2. Ensure those writes are durable.
3. Atomically publish the small `Reference` returned by `Root()`.

Objects are immutable and writes by content ID are naturally idempotent.
`Load` eagerly resolves and validates an entire generation. `Open` creates a
lazy `Snapshot` whose lookups and mutations resolve only touched paths through
a caller-provided `Resolver`.

Every encoded object starts with a structured eight-byte header: the four-byte
`GMTR` signature, a format-version byte, a `Kind` byte, and two reserved zero
bytes. The following format ID binds the codec, namespace, and trie parameters.

Snapshot mutations stage new objects in memory. `FinalChange()` returns the
reachable staged objects relative to the root originally passed to `Open`,
again children before parents. Persist every object in `Change.Objects` before
publishing `Change.Root`. Do not publish a staged root by itself: another
process cannot resolve the snapshot's in-memory overlay.

## Examples

- [`cmd/basic`](cmd/basic) — immutable updates and historical versions
- [`cmd/custom-codec`](cmd/custom-codec) — a canonical encoding for a struct
- [`cmd/lazy-storage`](cmd/lazy-storage) — lazy reads, staged updates, and safe
  generation publishing

Run any example from the repository root:

```sh
go run ./cmd/basic
go run ./cmd/custom-codec
go run ./cmd/lazy-storage
```

## Production notes

- Treat codec compatibility IDs and namespaces as schema identifiers. A
  mismatch deliberately prevents old objects from being opened.
- `Resolver` implementations should honor context cancellation and return
  `ErrNotFound` (possibly wrapped) when an object is absent.
- Apply deadlines, read-count quotas, and total-byte limits around untrusted
  roots. Per-object bounds do not limit the size of an eagerly loaded tree.
- Decoded objects are checked for their expected SHA-256 ID, format, canonical
  representation, reference summaries, depth, and path placement. Preserve
  these checks by using `Load`, `Open`, or `DecodeObject` for stored bytes.
- Encoded keys are limited to `MaximumKeyBytes`, values to
  `MaximumValueBytes`, leaves to `MaximumLeafEntries` and `MaximumLeafBytes`,
  and trie paths to `MaximumDepth`. `ErrBound` identifies size-limit failures.
- SHA-256 key-digest collisions are reported as `ErrCollision`; the package
  never silently combines distinct canonical keys.
- An empty root is bound to the complete format. Keep the full `Reference`,
  rather than reconstructing an empty value or persisting only its ID.

## Development

```sh
go test ./...
go test -race ./...
go test -bench=. -benchmem ./...
go vet ./...
```

Run the decoder fuzz target independently for sustained fuzzing:

```sh
go test -fuzz=FuzzDecodeObject -fuzztime=30s
```

## License

Released under the [MIT License](LICENSE).
