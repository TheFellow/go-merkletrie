# go-merkletrie

`go-merkletrie` is an immutable, generic, content-addressed radix trie for Go.
It preserves old versions after updates and can reopen persisted roots lazily.

The module requires Go 1.27.1 or later.

```sh
go get github.com/TheFellow/go-merkletrie@latest
```

## Quick start

Combine canonical key and value encodings into a codec, then create a tree:

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
	check(err)

	empty, err := merkletrie.New(codec)
	check(err)

	updated, changed, err := empty.Put("answer", 42)
	check(err)

	value, found, err := updated.Lookup("answer")
	check(err)

	fmt.Println(value, found, changed)       // 42 true true
	fmt.Println(empty.Len(), updated.Len()) // 0 1
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
```

`Put` and `Delete` return new trees; earlier versions remain unchanged and
safe for concurrent readers. Built-in encodings support strings, byte slices,
and fixed-width integers. Use `NewEncoding` for application types.

## Examples

- [`examples/basic`](examples/basic) — immutable updates and historical versions
- [`examples/content-addressed-files`](examples/content-addressed-files) — versioned file paths over deduplicated blobs
- [`examples/custom-codec`](examples/custom-codec) — a canonical struct encoding
- [`examples/lazy-storage`](examples/lazy-storage) — lazy reads and safe persistence

Run them from the repository root:

```sh
go run ./examples/basic
go run ./examples/content-addressed-files
go run ./examples/custom-codec
go run ./examples/lazy-storage
```

Read [Concepts and persistence](docs/concepts.md) for codecs, root semantics,
content-addressed storage, lazy snapshots, and production considerations.

## Inspecting a trie

The [`debug`](debug) package walks the physical trie and decodes leaf entries
into a human-readable description. It expands digests as hexadecimal strings
and includes routes, child slots, semantic summaries, and encoded sizes:

```go
description, err := triedebug.Inspect(tree, codec)
check(err)

for _, node := range description.Nodes {
	fmt.Printf("%s: %s (%d entries)\n",
		node.Route, node.Reference.Kind, node.Reference.Semantic.Count)
}
```

Import it as `triedebug "github.com/TheFellow/go-merkletrie/debug"`. Use
`triedebug.Walk` with a `triedebug.Visitor` to inspect large tries without
collecting every node. These diagnostics describe the current implementation
and are not a persistence format.

## Development

```sh
go test ./...
go test -race ./...
go test -bench=. -benchmem ./...
go test -fuzz=FuzzDecodeObject -fuzztime=30s
go vet ./...
```

## License

Released under the [MIT License](LICENSE).
