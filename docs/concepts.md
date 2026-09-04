# Concepts and persistence

This guide covers the protocol and storage details behind the quick start.

## Canonical codecs

A `Codec[K, V]` defines the canonical bytes for keys and values. These bytes
are part of the persisted protocol: encoders must be deterministic, distinct
logical keys must have distinct encodings, and decoding then re-encoding must
produce the same bytes.

Use `NewEncoding` and `NewCodec` to compose a codec, or implement `Codec`
directly. Change its compatibility ID whenever an encoding or its meaning
changes. `WithNamespace` separates independent trie formats that otherwise
share a codec. Both values must remain stable when reopening stored data.

## Roots and equality

`Tree.Root()` returns a `Reference` containing the root object's content ID and
a semantic summary. Equal non-empty root IDs prove identical encoded shape and
contents.

Physical roots are history-dependent. Deletion intentionally does not merge
internal nodes, so two trees containing the same entries can have different
root IDs. `Reference.Semantic` is shape-independent, but its fingerprint is
only an equality hint—not cryptographic proof. Compare entries when false
equality would matter.

`Tree.Entries()` returns a lazy sequence of decoded key/value pairs. Its order
is deterministic but intentionally unspecified.

## Content-addressed persistence

`Tree.Objects()` returns every reachable encoded object once, with children
before parents. To publish a generation safely:

1. Store every object's `Payload` under its `ID`.
2. Ensure those writes are durable.
3. Atomically publish the `Reference` returned by `Root()`.

Objects are immutable, so writes by content ID are idempotent. `Load` eagerly
resolves and validates a complete generation. `Open` creates a lazy `Snapshot`
whose operations resolve only touched paths through a caller-provided
`Resolver`.

Snapshot mutations stage objects in memory. `FinalChange()` returns the
reachable staged objects relative to the root passed to `Open`, again with
children before parents. Persist every object in `Change.Objects` before
publishing `Change.Root`.

## Object format

Every object starts with an eight-byte header: the `GMTR` signature, a format
version byte, a `Kind` byte, and two reserved zero bytes. The following format
ID binds the codec, namespace, and trie parameters. Decoding validates the
content ID, format, canonical representation, summaries, depth, and routing.

Empty roots are also format-bound. Persist the complete `Reference`, rather
than reconstructing an empty value or storing only its ID.

## Production considerations

- Resolvers should honor context cancellation and return `ErrNotFound`,
  possibly wrapped, for an absent object.
- Apply deadlines, read-count quotas, and total-byte limits to untrusted roots.
  Per-object bounds do not limit an eagerly loaded tree's total size.
- Keys, values, leaves, and paths have exported hard limits. `ErrBound`
  identifies size-limit failures.
- SHA-256 key-digest collisions return `ErrCollision`; distinct keys are never
  silently combined.
- Treat codec compatibility IDs and namespaces as persisted schema identifiers.
