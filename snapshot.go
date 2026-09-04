package merkletrie

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
)

// Snapshot is a lazily resolved immutable trie. Lookup and mutation read only
// the selected root-to-leaf path; derived snapshots share staged immutable
// objects while retaining independent logical roots.
type Snapshot[K, V any] struct {
	codec    Codec[K, V]
	format   Digest
	root     Reference
	baseRoot Reference
	resolver Resolver
	overlay  *snapshotOverlay
}

type snapshotOverlay struct {
	mu      sync.RWMutex
	objects map[Digest]EncodedObject
	base    map[Digest]struct{}
}

// Open constructs a lazy snapshot over root. An empty root needs no resolver.
func Open[K, V any](codec Codec[K, V], root Reference, resolver Resolver, options ...Option) (Snapshot[K, V], error) {
	tree, err := New(codec, options...)
	if err != nil {
		return Snapshot[K, V]{}, err
	}
	if root == emptyReference(tree.format) {
		resolver = nil
	} else {
		if root.Kind == KindEmpty {
			return Snapshot[K, V]{}, fmt.Errorf("%w: empty root format mismatch", ErrInvalidRoot)
		}
		if err := validateReference(root); err != nil {
			return Snapshot[K, V]{}, err
		}
		if resolver == nil {
			return Snapshot[K, V]{}, fmt.Errorf("%w: populated root has no resolver", ErrNotFound)
		}
	}
	return Snapshot[K, V]{
		codec: codec, format: tree.format, root: root, baseRoot: root, resolver: resolver,
		overlay: &snapshotOverlay{objects: make(map[Digest]EncodedObject), base: make(map[Digest]struct{})},
	}, nil
}

// Root returns the snapshot's physical root reference.
func (s Snapshot[K, V]) Root() Reference { return s.root }

// FormatID returns the persisted format identity.
func (s Snapshot[K, V]) FormatID() Digest { return s.format }

// Lookup resolves only the path selected by key.
func (s Snapshot[K, V]) Lookup(ctx context.Context, key K) (value V, found bool, err error) {
	tree := Tree[K, V]{codec: s.codec, format: s.format}
	encoded, err := tree.encodeKey(key)
	if err != nil {
		return value, false, err
	}
	digest := keyDigest(s.format, encoded)
	ref := s.root
	for depth := uint8(0); ref.Kind != KindEmpty; depth++ {
		document, err := s.resolve(ctx, ref, depth)
		if err != nil {
			return value, false, err
		}
		if document.Kind == KindLeaf {
			entries := internalEntries(s.format, document.Entries)
			if err := validateLeafPrefix(entries, digest, depth); err != nil {
				return value, false, err
			}
			i, found, collision := leafSearch(entries, digest, encoded)
			if collision {
				return value, false, ErrCollision
			}
			if !found {
				return value, false, nil
			}
			value, err = s.codec.DecodeValue(bytes.Clone(entries[i].value))
			return value, err == nil, err
		}
		ref = childAt(document.Children, uint8(digestNibble(digest, int(depth))))
		if ref == (Reference{}) {
			return value, false, nil
		}
	}
	return value, false, nil
}

// Put stages an insertion or replacement and returns a derived snapshot.
func (s Snapshot[K, V]) Put(ctx context.Context, key K, value V) (Snapshot[K, V], bool, error) {
	tree := Tree[K, V]{codec: s.codec, format: s.format}
	encodedKey, err := tree.encodeKey(key)
	if err != nil {
		return s, false, err
	}
	encodedValue, err := tree.encodeValue(value)
	if err != nil {
		return s, false, err
	}
	e := newEntry(s.format, encodedKey, encodedValue)
	root, objects, changed, err := s.put(ctx, s.root, 0, e)
	if err != nil || !changed {
		return s, changed, err
	}
	s.overlay.add(objects)
	s.root = root
	return s, true, nil
}

func (s Snapshot[K, V]) put(ctx context.Context, ref Reference, depth uint8, e entry) (Reference, []EncodedObject, bool, error) {
	if ref.Kind == KindEmpty || ref == (Reference{}) {
		document, err := leafDocument(s.format, depth, []entry{e})
		return documentReference(document), []EncodedObject{document}, true, err
	}
	document, err := s.resolve(ctx, ref, depth)
	if err != nil {
		return Reference{}, nil, false, err
	}
	if document.Kind == KindLeaf {
		entries := internalEntries(s.format, document.Entries)
		if err := validateLeafPrefix(entries, e.keyDigest, depth); err != nil {
			return Reference{}, nil, false, err
		}
		i, found, collision := leafSearch(entries, e.keyDigest, e.key)
		if collision {
			return Reference{}, nil, false, ErrCollision
		}
		if found && bytes.Equal(entries[i].value, e.value) {
			return ref, nil, false, nil
		}
		if found {
			entries[i] = e
		} else {
			entries = append(entries, entry{})
			copy(entries[i+1:], entries[i:])
			entries[i] = e
		}
		root, objects, err := subtreeDocuments(s.format, depth, entries)
		return root, objects, true, err
	}
	slot := uint8(digestNibble(e.keyDigest, int(depth)))
	children := slices.Clone(document.Children)
	childRoot, objects, changed, err := s.put(ctx, childAt(children, slot), depth+1, e)
	if err != nil || !changed {
		return ref, nil, changed, err
	}
	children = setChild(children, slot, childRoot)
	parent, err := nodeDocument(s.format, depth, children)
	return documentReference(parent), append(objects, parent), true, err
}

// Delete stages removal of key and returns a derived snapshot.
func (s Snapshot[K, V]) Delete(ctx context.Context, key K) (Snapshot[K, V], bool, error) {
	tree := Tree[K, V]{codec: s.codec, format: s.format}
	encoded, err := tree.encodeKey(key)
	if err != nil {
		return s, false, err
	}
	root, objects, changed, err := s.delete(ctx, s.root, 0, keyDigest(s.format, encoded), encoded)
	if err != nil || !changed {
		return s, changed, err
	}
	if root == (Reference{}) {
		root = emptyReference(s.format)
	}
	s.overlay.add(objects)
	s.root = root
	return s, true, nil
}

func (s Snapshot[K, V]) delete(ctx context.Context, ref Reference, depth uint8, digest Digest, key []byte) (Reference, []EncodedObject, bool, error) {
	if ref.Kind == KindEmpty || ref == (Reference{}) {
		return ref, nil, false, nil
	}
	document, err := s.resolve(ctx, ref, depth)
	if err != nil {
		return Reference{}, nil, false, err
	}
	if document.Kind == KindLeaf {
		entries := internalEntries(s.format, document.Entries)
		i, found, collision := leafSearch(entries, digest, key)
		if collision {
			return Reference{}, nil, false, ErrCollision
		}
		if !found {
			return ref, nil, false, nil
		}
		entries = slices.Delete(entries, i, i+1)
		if len(entries) == 0 {
			return Reference{}, nil, true, nil
		}
		leaf, err := leafDocument(s.format, depth, entries)
		return documentReference(leaf), []EncodedObject{leaf}, true, err
	}
	slot := uint8(digestNibble(digest, int(depth)))
	children := slices.Clone(document.Children)
	childRoot, objects, changed, err := s.delete(ctx, childAt(children, slot), depth+1, digest, key)
	if err != nil || !changed {
		return ref, nil, changed, err
	}
	children = setChild(children, slot, childRoot)
	if len(children) == 0 {
		return Reference{}, objects, true, nil
	}
	parent, err := nodeDocument(s.format, depth, children)
	return documentReference(parent), append(objects, parent), true, err
}

// Change is the reachable staged object set relative to the root passed to Open.
type Change struct {
	// Base is the root originally passed to Open.
	Base Reference
	// Root is the snapshot root after staged mutations.
	Root Reference
	// Objects contains newly reachable objects in children-before-parent order.
	Objects []EncodedObject
}

// FinalChange returns reachable newly staged objects in children-before-parent
// order. Persist all Objects before publishing Root.
func (s Snapshot[K, V]) FinalChange() Change {
	change := Change{Base: s.baseRoot, Root: s.root}
	if s.root == s.baseRoot {
		return change
	}
	s.overlay.mu.RLock()
	defer s.overlay.mu.RUnlock()
	seen := make(map[Digest]struct{})
	var visit func(Reference)
	visit = func(ref Reference) {
		if ref.Kind == KindEmpty {
			return
		}
		if _, ok := seen[ref.ID]; ok {
			return
		}
		document, ok := s.overlay.objects[ref.ID]
		if !ok {
			return
		}
		if _, base := s.overlay.base[ref.ID]; base {
			return
		}
		seen[ref.ID] = struct{}{}
		for _, child := range document.Children {
			visit(child.Reference)
		}
		change.Objects = append(change.Objects, cloneDocument(document))
	}
	visit(s.root)
	return change
}

func (s Snapshot[K, V]) resolve(ctx context.Context, ref Reference, depth uint8) (EncodedObject, error) {
	if document, ok := s.overlay.get(ref.ID); ok {
		return validateResolved(document, s.format, ref, depth)
	}
	payload, err := s.resolver.Resolve(ctx, ref)
	if err != nil {
		return EncodedObject{}, fmt.Errorf("resolve object %x: %w", ref.ID, err)
	}
	document, err := decodeObjectWithFormat(s.codec, s.format, payload, ref.ID)
	if err != nil {
		return EncodedObject{}, err
	}
	document, err = validateResolved(document, s.format, ref, depth)
	if err == nil {
		s.overlay.markBase(ref.ID)
	}
	return document, err
}

func validateResolved(document EncodedObject, format Digest, ref Reference, depth uint8) (EncodedObject, error) {
	if document.Format != format || document.Kind != ref.Kind || document.Semantic != ref.Semantic || document.Depth != depth {
		return EncodedObject{}, fmt.Errorf("%w: resolved object mismatch", ErrCorrupt)
	}
	return document, nil
}

func internalEntries(format Digest, encoded []EncodedEntry) []entry {
	entries := make([]entry, len(encoded))
	for i, e := range encoded {
		entries[i] = newEntry(format, e.Key, e.Value)
	}
	return entries
}

func validateLeafPrefix(entries []entry, digest Digest, depth uint8) error {
	for _, e := range entries {
		if !digestPrefixMatches(e.keyDigest, digest, depth) {
			return fmt.Errorf("%w: leaf entry outside path", ErrCorrupt)
		}
	}
	return nil
}

func leafDocument(format Digest, depth uint8, entries []entry) (EncodedObject, error) {
	o, err := buildLeaf(format, depth, entries)
	if err != nil {
		return EncodedObject{}, err
	}
	return objectDocument(format, o), nil
}

func subtreeDocuments(format Digest, depth uint8, entries []entry) (Reference, []EncodedObject, error) {
	o, err := buildObject(format, depth, entries)
	if err != nil {
		return Reference{}, nil, err
	}
	tree := Tree[struct{}, struct{}]{format: format, root: o}
	return objectReference(o), tree.Objects(), nil
}

func nodeDocument(format Digest, depth uint8, children []ChildReference) (EncodedObject, error) {
	var summaries [fanout]*object
	for _, child := range children {
		if err := validateReference(child.Reference); err != nil {
			return EncodedObject{}, err
		}
		summary := &object{depth: depth + 1, semantic: child.Reference.Semantic, content: child.Reference.ID}
		if child.Reference.Kind == KindLeaf {
			summary.leaf = []entry{}
		}
		summaries[child.Slot] = summary
	}
	o, err := buildNode(format, depth, summaries)
	if err != nil {
		return EncodedObject{}, err
	}
	return objectDocument(format, o), nil
}

func documentReference(document EncodedObject) Reference {
	return Reference{Kind: document.Kind, ID: document.ID, Semantic: document.Semantic}
}

func childAt(children []ChildReference, slot uint8) Reference {
	i, found := slices.BinarySearchFunc(children, slot, func(child ChildReference, slot uint8) int { return int(child.Slot) - int(slot) })
	if !found {
		return Reference{}
	}
	return children[i].Reference
}

func setChild(children []ChildReference, slot uint8, ref Reference) []ChildReference {
	i, found := slices.BinarySearchFunc(children, slot, func(child ChildReference, slot uint8) int { return int(child.Slot) - int(slot) })
	if ref == (Reference{}) {
		if found {
			return slices.Delete(children, i, i+1)
		}
		return children
	}
	if found {
		children[i].Reference = ref
		return children
	}
	children = append(children, ChildReference{})
	copy(children[i+1:], children[i:])
	children[i] = ChildReference{Slot: slot, Reference: ref}
	return children
}

func (o *snapshotOverlay) add(documents []EncodedObject) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, document := range documents {
		o.objects[document.ID] = cloneDocument(document)
	}
}
func (o *snapshotOverlay) get(id Digest) (EncodedObject, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	document, ok := o.objects[id]
	return cloneDocument(document), ok
}
func (o *snapshotOverlay) markBase(id Digest) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.base[id] = struct{}{}
}
func cloneDocument(document EncodedObject) EncodedObject {
	document.Payload = slices.Clone(document.Payload)
	document.Children = slices.Clone(document.Children)
	document.Entries = slices.Clone(document.Entries)
	for i := range document.Entries {
		document.Entries[i].Key = slices.Clone(document.Entries[i].Key)
		document.Entries[i].Value = slices.Clone(document.Entries[i].Value)
	}
	return document
}
