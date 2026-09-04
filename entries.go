package merkletrie

import (
	"bytes"
	"fmt"
	"iter"
)

// Entry is one decoded key/value pair returned by Tree.Entries.
type Entry[K, V any] struct {
	Key   K
	Value V
}

// Entries returns a lazy sequence over the tree's logical entries. Iteration
// order is deterministic for a particular format but is not part of the
// compatibility contract. The sequence stops after a decoding error.
//
// The tree already validated every canonical entry on insertion or load, so
// an error indicates that a codec's behavior changed or is nondeterministic.
func (t Tree[K, V]) Entries() iter.Seq2[Entry[K, V], error] {
	return func(yield func(Entry[K, V], error) bool) {
		if t.codec == nil || t.format == (Digest{}) {
			var zero Entry[K, V]
			yield(zero, fmt.Errorf("%w: uninitialized tree", ErrCorrupt))
			return
		}
		var walk func(*object) bool
		walk = func(o *object) bool {
			if o == nil {
				return true
			}
			if !o.isLeaf() {
				for _, child := range o.children {
					if !walk(child) {
						return false
					}
				}
				return true
			}
			for _, encoded := range o.leaf {
				key, err := t.codec.DecodeKey(bytes.Clone(encoded.key))
				if err != nil {
					var zero Entry[K, V]
					yield(zero, fmt.Errorf("decode key: %w", err))
					return false
				}
				value, err := t.codec.DecodeValue(bytes.Clone(encoded.value))
				if err != nil {
					var zero Entry[K, V]
					yield(zero, fmt.Errorf("decode value: %w", err))
					return false
				}
				if !yield(Entry[K, V]{Key: key, Value: value}, nil) {
					return false
				}
			}
			return true
		}
		walk(t.root)
	}
}
