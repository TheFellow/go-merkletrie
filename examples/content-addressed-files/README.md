# Content-addressed files

This example uses a Merkle trie as a versioned index from logical file paths
to content-addressed blob metadata. Blob bytes and encoded trie objects are
stored on disk by SHA-256 digest.

It demonstrates:

- deduplicating files with identical contents;
- keeping large file bytes outside the trie's bounded values;
- updating a file while retaining access through the old root;
- persisting new trie objects before publishing a new root; and
- lazily reopening both generations from disk.

The temporary object store is removed when the program exits. A production
store would additionally serialize and atomically publish the complete
`merkletrie.Reference` for its current generation.

```sh
go run ./examples/content-addressed-files
```
