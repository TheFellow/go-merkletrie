package inspect_test

import (
	"fmt"
	"strings"

	"github.com/TheFellow/go-merkletrie"
	"github.com/TheFellow/go-merkletrie/inspect"
)

func ExampleDescribe() {
	codec, _ := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.Uint64Encoding())
	tree, _ := merkletrie.New(codec)
	for i := range merkletrie.MaximumLeafEntries + 1 {
		tree, _, _ = tree.Put(fmt.Sprintf("key-%03d", i), uint64(i))
	}

	description, _ := inspect.Describe(tree, codec)
	root := description.Nodes[0]
	routes := make([]string, len(root.Children))
	for i, child := range root.Children {
		routes[i] = child.Route
	}

	leafCount, decodedEntries := 0, 0
	for _, node := range description.Nodes {
		if node.Reference.Kind == "leaf" {
			leafCount++
			decodedEntries += len(node.Entries)
		}
	}

	fmt.Printf("root: %s with %d entries\n", root.Reference.Kind, root.Reference.Semantic.Count)
	fmt.Printf("occupied routes: %s\n", strings.Join(routes, " "))
	fmt.Printf("walked %d leaves containing %d decoded entries\n", leafCount, decodedEntries)

	// Output:
	// root: node with 129 entries
	// occupied routes: 0 1 2 3 4 5 6 7 8 9 a b c d e f
	// walked 16 leaves containing 129 decoded entries
}
