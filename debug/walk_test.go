package debug_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	merkletrie "github.com/TheFellow/go-merkletrie"
	"github.com/TheFellow/go-merkletrie/debug"
)

func TestInspectLeaf(t *testing.T) {
	codec := stringUintCodec(t)
	tree, err := merkletrie.New(codec)
	if err != nil {
		t.Fatal(err)
	}
	tree, _, err = tree.Put("answer", 42)
	if err != nil {
		t.Fatal(err)
	}

	description, err := debug.Inspect(tree, codec)
	if err != nil {
		t.Fatal(err)
	}
	if description.ProtocolVersion != merkletrie.ProtocolVersion || len(description.Nodes) != 1 {
		t.Fatalf("unexpected description: %+v", description)
	}
	node := description.Nodes[0]
	if node.Route != "root" || node.Reference.Kind != "leaf" || node.Reference.Semantic.Count != 1 || node.Depth != 0 {
		t.Fatalf("unexpected leaf: %+v", node)
	}
	if len(node.Entries) != 1 || node.Entries[0].Key != "answer" || node.Entries[0].Value != 42 ||
		node.Entries[0].EncodedKey != "616e73776572" || node.Entries[0].EncodedValue != "000000000000002a" {
		t.Fatalf("unexpected entry: %+v", node.Entries)
	}
	if _, err := json.MarshalIndent(description, "", "  "); err != nil {
		t.Fatalf("description is not JSON-marshalable: %v", err)
	}
}

func TestWalkInternalNodesInRootFirstSlotOrder(t *testing.T) {
	codec := stringUintCodec(t)
	tree, err := merkletrie.New(codec)
	if err != nil {
		t.Fatal(err)
	}
	for i := range merkletrie.MaximumLeafEntries + 1 {
		tree, _, err = tree.Put(fmt.Sprintf("key-%03d", i), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
	}

	var nodes []debug.Node[string, uint64]
	err = debug.Walk(tree, codec, debug.VisitorFunc[string, uint64](func(node debug.Node[string, uint64]) error {
		nodes = append(nodes, node)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) < 2 || nodes[0].Reference.Kind != "node" || nodes[0].Route != "root" {
		t.Fatalf("expected an internal root followed by children: %+v", nodes)
	}
	for i, child := range nodes[0].Children {
		if nodes[i+1].Route != child.Route {
			t.Fatalf("child %d visited at %q; want %q", i, nodes[i+1].Route, child.Route)
		}
		if i > 0 && nodes[0].Children[i-1].Slot >= child.Slot {
			t.Fatalf("children are not in slot order: %+v", nodes[0].Children)
		}
	}

	stop := errors.New("stop")
	calls := 0
	err = debug.Walk(tree, codec, debug.VisitorFunc[string, uint64](func(debug.Node[string, uint64]) error {
		calls++
		return stop
	}))
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("visitor stop: calls=%d err=%v", calls, err)
	}
}

func TestWalkEmptyTree(t *testing.T) {
	codec := stringUintCodec(t)
	tree, err := merkletrie.New(codec)
	if err != nil {
		t.Fatal(err)
	}
	description, err := debug.Inspect(tree, codec)
	if err != nil {
		t.Fatal(err)
	}
	if len(description.Nodes) != 1 || description.Nodes[0].Reference.Kind != "empty" || description.Nodes[0].Route != "root" {
		t.Fatalf("unexpected empty tree: %+v", description)
	}
}

func TestWalkRejectsInvalidArguments(t *testing.T) {
	codec := stringUintCodec(t)
	tree, err := merkletrie.New(codec)
	if err != nil {
		t.Fatal(err)
	}
	other, err := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.Uint32Encoding())
	if err != nil {
		t.Fatal(err)
	}
	visitor := debug.VisitorFunc[string, uint64](func(debug.Node[string, uint64]) error { return nil })
	if err := debug.Walk(tree, nil, visitor); !errors.Is(err, debug.ErrInvalidArgument) {
		t.Fatalf("nil codec error = %v", err)
	}
	if err := debug.Walk(tree, codec, nil); !errors.Is(err, debug.ErrInvalidArgument) {
		t.Fatalf("nil visitor error = %v", err)
	}
	if err := debug.Walk(tree, mismatchedCodec{other}, visitor); !errors.Is(err, debug.ErrInvalidArgument) {
		t.Fatalf("mismatched codec error = %v", err)
	}
	var zero merkletrie.Tree[string, uint64]
	if err := debug.Walk(zero, codec, visitor); !errors.Is(err, debug.ErrInvalidArgument) {
		t.Fatalf("zero tree error = %v", err)
	}
}

type mismatchedCodec struct {
	codec merkletrie.PairCodec[string, uint32]
}

func (m mismatchedCodec) CompatibilityID() merkletrie.Digest         { return m.codec.CompatibilityID() }
func (m mismatchedCodec) EncodeKey(key string) ([]byte, error)       { return []byte(key), nil }
func (m mismatchedCodec) DecodeKey(encoded []byte) (string, error)   { return string(encoded), nil }
func (m mismatchedCodec) EncodeValue(value uint64) ([]byte, error)   { return nil, nil }
func (m mismatchedCodec) DecodeValue(encoded []byte) (uint64, error) { return 0, nil }

func stringUintCodec(t *testing.T) merkletrie.PairCodec[string, uint64] {
	t.Helper()
	codec, err := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	return codec
}
