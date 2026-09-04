package merkletrie

import (
	"bytes"
	"context"
	"fmt"
)

// Resolver loads the canonical payload for a content-addressed reference.
type Resolver interface {
	Resolve(context.Context, Reference) ([]byte, error)
}

// ResolverFunc adapts a function to Resolver.
type ResolverFunc func(context.Context, Reference) ([]byte, error)

// Resolve implements Resolver.
func (f ResolverFunc) Resolve(ctx context.Context, ref Reference) ([]byte, error) { return f(ctx, ref) }

// Load reconstructs and validates an immutable tree from a root reference.
// Every reachable object is resolved and checked before Load succeeds. An
// empty root requires no resolver.
func Load[K, V any](ctx context.Context, codec Codec[K, V], root Reference, resolver Resolver, options ...Option) (Tree[K, V], error) {
	tree, err := New(codec, options...)
	if err != nil {
		return Tree[K, V]{}, err
	}
	if root == emptyReference(tree.format) {
		return tree, nil
	}
	if root.Kind == KindEmpty {
		return Tree[K, V]{}, fmt.Errorf("%w: empty root format mismatch", ErrInvalidRoot)
	}
	if err := validateReference(root); err != nil {
		return Tree[K, V]{}, err
	}
	if resolver == nil {
		return Tree[K, V]{}, fmt.Errorf("%w: nil resolver", ErrNotFound)
	}
	seen := make(map[Digest]struct{})
	loaded, err := loadObject(ctx, codec, tree.format, root, 0, Digest{}, resolver, seen)
	if err != nil {
		return Tree[K, V]{}, err
	}
	tree.root = loaded
	return tree, nil
}

func loadObject[K, V any](ctx context.Context, codec Codec[K, V], format Digest, ref Reference, depth uint8, prefix Digest, resolver Resolver, seen map[Digest]struct{}) (*object, error) {
	if _, duplicate := seen[ref.ID]; duplicate {
		return nil, fmt.Errorf("%w: repeated or cyclic object reference", ErrCorrupt)
	}
	seen[ref.ID] = struct{}{}
	payload, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("resolve object %x: %w", ref.ID, err)
	}
	document, err := decodeObjectWithFormat(codec, format, payload, ref.ID)
	if err != nil {
		return nil, err
	}
	if document.Format != format || document.Kind != ref.Kind || document.Semantic != ref.Semantic || document.Depth != depth {
		return nil, fmt.Errorf("%w: object does not match reference", ErrCorrupt)
	}
	if document.Kind == KindLeaf {
		entries := make([]entry, len(document.Entries))
		for i, encoded := range document.Entries {
			entries[i] = newEntry(format, encoded.Key, encoded.Value)
			if !digestPrefixMatches(entries[i].keyDigest, prefix, depth) {
				return nil, fmt.Errorf("%w: leaf entry outside path", ErrCorrupt)
			}
		}
		leaf, err := buildLeaf(format, depth, entries)
		if err != nil || leaf.content != ref.ID {
			return nil, fmt.Errorf("%w: invalid loaded leaf", ErrCorrupt)
		}
		return leaf, nil
	}
	var children [fanout]*object
	for _, child := range document.Children {
		childPrefix := prefix
		setDigestNibble(&childPrefix, int(depth), int(child.Slot))
		loaded, err := loadObject(ctx, codec, format, child.Reference, depth+1, childPrefix, resolver, seen)
		if err != nil {
			return nil, err
		}
		children[child.Slot] = loaded
	}
	node, err := buildNode(format, depth, children)
	if err != nil || node.content != ref.ID || !bytes.Equal(node.encoded, payload) {
		return nil, fmt.Errorf("%w: invalid loaded node", ErrCorrupt)
	}
	return node, nil
}

func validateReference(ref Reference) error {
	if ref.Kind != KindLeaf && ref.Kind != KindNode || ref.ID == (Digest{}) || ref.Semantic.Count == 0 ||
		ref.Kind == KindLeaf && ref.Semantic.Count > MaximumLeafEntries {
		return fmt.Errorf("%w: invalid reference", ErrCorrupt)
	}
	return nil
}

func digestPrefixMatches(digest, prefix Digest, depth uint8) bool {
	for i := range int(depth) {
		if digestNibble(digest, i) != digestNibble(prefix, i) {
			return false
		}
	}
	return true
}

func setDigestNibble(digest *Digest, depth, nibble int) {
	if depth%2 == 0 {
		digest[depth/2] = digest[depth/2]&0x0f | byte(nibble<<4)
	} else {
		digest[depth/2] = digest[depth/2]&0xf0 | byte(nibble)
	}
}
