package inspect_test

import (
	"fmt"

	merkletrie "github.com/TheFellow/go-merkletrie"
	"github.com/TheFellow/go-merkletrie/inspect"
)

func ExampleDescribe() {
	codec, _ := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.Uint64Encoding())
	tree, _ := merkletrie.New(codec)
	tree, _, _ = tree.Put("answer", 42)

	description, _ := inspect.Describe(tree, codec)
	for _, node := range description.Nodes {
		fmt.Printf("%s: %s (%d entries)\n",
			node.Route, node.Reference.Kind, node.Reference.Semantic.Count)
		for _, entry := range node.Entries {
			fmt.Printf("  %q = %d\n", entry.Key, entry.Value)
		}
	}

	// Output:
	// root: leaf (1 entries)
	//   "answer" = 42
}
