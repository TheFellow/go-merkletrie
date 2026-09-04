# Lazy content-addressed storage

This example persists a tree into an in-memory object store, lazily opens it,
stages changes, and safely publishes the resulting generation.

```sh
go run ./cmd/lazy-storage
```
