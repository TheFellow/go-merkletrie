package inspect

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"

	merkletrie "github.com/TheFellow/go-merkletrie"
)

// ErrInvalidArgument indicates that Walk or Describe received an unusable
// codec, tree, or visitor.
var ErrInvalidArgument = errors.New("merkletrie/inspect: invalid argument")

// Summary is the human-readable form of a subtree's semantic root.
type Summary struct {
	Count       uint64 `json:"count"`
	Fingerprint string `json:"fingerprint"`
}

// Reference is the human-readable form of a trie object reference.
type Reference struct {
	Kind     string  `json:"kind"`
	ID       string  `json:"id"`
	Semantic Summary `json:"semantic"`
}

// Entry is one decoded leaf entry together with its canonical representation.
// The encoded fields are hexadecimal so the value remains convenient to read
// after JSON marshaling.
type Entry[K, V any] struct {
	Key          K      `json:"key"`
	Value        V      `json:"value"`
	EncodedKey   string `json:"encoded_key"`
	EncodedValue string `json:"encoded_value"`
}

// Child describes one occupied slot of an internal node. Route is the full
// slash-separated hexadecimal route from the root to the child.
type Child struct {
	Slot      uint8     `json:"slot"`
	SlotHex   string    `json:"slot_hex"`
	Route     string    `json:"route"`
	Reference Reference `json:"reference"`
}

// Node is the unpacked, human-readable form passed to a Visitor. Route is
// "root" for the root object and otherwise lists its hexadecimal trie slots,
// for example "a/3". Nodes are detached from the source tree.
type Node[K, V any] struct {
	Route       string        `json:"route"`
	Reference   Reference     `json:"reference"`
	Depth       uint8         `json:"depth"`
	EncodedSize int           `json:"encoded_size"`
	Entries     []Entry[K, V] `json:"entries,omitempty"`
	Children    []Child       `json:"children,omitempty"`
}

// Description is a collected inspection of a tree. It is convenient for
// debugger watches and JSON output. Nodes are in root-first traversal order.
type Description[K, V any] struct {
	ProtocolVersion string       `json:"protocol_version"`
	CompatibilityID string       `json:"compatibility_id"`
	FormatID        string       `json:"format_id"`
	Root            Reference    `json:"root"`
	Nodes           []Node[K, V] `json:"nodes"`
}

// Visitor receives each node in deterministic, root-first order. Returning an
// error stops the walk and returns that error from Walk.
type Visitor[K, V any] interface {
	Visit(Node[K, V]) error
}

// VisitorFunc adapts a function to Visitor.
type VisitorFunc[K, V any] func(Node[K, V]) error

// Visit implements Visitor.
func (f VisitorFunc[K, V]) Visit(node Node[K, V]) error { return f(node) }

// Walk visits the tree's physical objects in root-first, slot order. The codec
// is used to turn canonical leaf bytes back into application values and must
// have the same compatibility ID as the tree's codec. An empty tree produces
// one node of kind "empty".
func Walk[K, V any](tree merkletrie.Tree[K, V], codec merkletrie.Codec[K, V], visitor Visitor[K, V]) error {
	if nilLike(codec) {
		return fmt.Errorf("%w: nil codec", ErrInvalidArgument)
	}
	if nilLike(visitor) {
		return fmt.Errorf("%w: nil visitor", ErrInvalidArgument)
	}
	compatibility := tree.CompatibilityID()
	format := tree.FormatID()
	if compatibility == (merkletrie.Digest{}) || format == (merkletrie.Digest{}) {
		return fmt.Errorf("%w: uninitialized tree", ErrInvalidArgument)
	}
	if codec.CompatibilityID() != compatibility {
		return fmt.Errorf("%w: codec compatibility ID does not match tree", ErrInvalidArgument)
	}

	root := tree.Root()
	if root.Kind == merkletrie.KindEmpty {
		return visitor.Visit(Node[K, V]{Route: "root", Reference: readableReference(root)})
	}

	documents := make(map[merkletrie.Digest]merkletrie.EncodedObject)
	for _, document := range tree.Objects() {
		documents[document.ID] = document
	}

	var visit func(merkletrie.Reference, []uint8) error
	visit = func(reference merkletrie.Reference, slots []uint8) error {
		document, ok := documents[reference.ID]
		if !ok {
			return fmt.Errorf("merkletrie/inspect: object %x is missing", reference.ID)
		}
		node := Node[K, V]{
			Route:       route(slots),
			Reference:   readableReference(reference),
			Depth:       document.Depth,
			EncodedSize: len(document.Payload),
		}
		if document.Kind == merkletrie.KindLeaf {
			node.Entries = make([]Entry[K, V], 0, len(document.Entries))
			for _, encoded := range document.Entries {
				key, err := codec.DecodeKey(bytes.Clone(encoded.Key))
				if err != nil {
					return fmt.Errorf("merkletrie/inspect: decode key in %s: %w", node.Route, err)
				}
				value, err := codec.DecodeValue(bytes.Clone(encoded.Value))
				if err != nil {
					return fmt.Errorf("merkletrie/inspect: decode value in %s: %w", node.Route, err)
				}
				node.Entries = append(node.Entries, Entry[K, V]{
					Key: key, Value: value,
					EncodedKey: hex.EncodeToString(encoded.Key), EncodedValue: hex.EncodeToString(encoded.Value),
				})
			}
		} else {
			node.Children = make([]Child, 0, len(document.Children))
			for _, child := range document.Children {
				childSlots := appendSlot(slots, child.Slot)
				node.Children = append(node.Children, Child{
					Slot: child.Slot, SlotHex: fmt.Sprintf("%x", child.Slot),
					Route: route(childSlots), Reference: readableReference(child.Reference),
				})
			}
		}
		if err := visitor.Visit(node); err != nil {
			return err
		}
		for _, child := range document.Children {
			if err := visit(child.Reference, appendSlot(slots, child.Slot)); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, nil)
}

// Describe collects the same human-readable nodes produced by Walk.
func Describe[K, V any](tree merkletrie.Tree[K, V], codec merkletrie.Codec[K, V]) (Description[K, V], error) {
	description := Description[K, V]{
		ProtocolVersion: merkletrie.ProtocolVersion,
		CompatibilityID: digest(tree.CompatibilityID()),
		FormatID:        digest(tree.FormatID()),
		Root:            readableReference(tree.Root()),
	}
	err := Walk(tree, codec, VisitorFunc[K, V](func(node Node[K, V]) error {
		description.Nodes = append(description.Nodes, node)
		return nil
	}))
	if err != nil {
		return Description[K, V]{}, err
	}
	return description, nil
}

func readableReference(reference merkletrie.Reference) Reference {
	return Reference{
		Kind: kind(reference.Kind), ID: digest(reference.ID),
		Semantic: Summary{Count: reference.Semantic.Count, Fingerprint: digest(reference.Semantic.Fingerprint)},
	}
}

func kind(value merkletrie.Kind) string {
	switch value {
	case merkletrie.KindEmpty:
		return "empty"
	case merkletrie.KindLeaf:
		return "leaf"
	case merkletrie.KindNode:
		return "node"
	default:
		return fmt.Sprintf("unknown(%d)", value)
	}
}

func digest(value merkletrie.Digest) string { return hex.EncodeToString(value[:]) }

func route(slots []uint8) string {
	if len(slots) == 0 {
		return "root"
	}
	result := make([]byte, 0, len(slots)*2-1)
	for i, slot := range slots {
		if i != 0 {
			result = append(result, '/')
		}
		result = append(result, "0123456789abcdef"[slot])
	}
	return string(result)
}

func appendSlot(slots []uint8, slot uint8) []uint8 {
	result := make([]uint8, len(slots)+1)
	copy(result, slots)
	result[len(slots)] = slot
	return result
}

func nilLike(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
