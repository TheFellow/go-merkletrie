// Command basic demonstrates immutable updates and historical versions.
package main

import (
	"fmt"
	"log"

	"github.com/TheFellow/go-merkletrie"
)

func main() {
	codec, err := merkletrie.NewCodec(merkletrie.StringEncoding(), merkletrie.Uint64Encoding())
	if err != nil {
		log.Fatal(err)
	}

	empty, err := merkletrie.New(codec)
	if err != nil {
		log.Fatal(err)
	}
	one, _, err := empty.Put("apples", 12)
	if err != nil {
		log.Fatal(err)
	}
	two, _, err := one.Put("oranges", 7)
	if err != nil {
		log.Fatal(err)
	}

	// Updates return a new tree; previous versions remain unchanged.
	_, inOne, err := one.Lookup("oranges")
	if err != nil {
		log.Fatal(err)
	}
	oranges, inTwo, err := two.Lookup("oranges")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("one: len=%d contains oranges=%v\n", one.Len(), inOne)
	fmt.Printf("two: len=%d oranges=%d found=%v\n", two.Len(), oranges, inTwo)
	fmt.Printf("root changed: %v\n", one.Root().ID != two.Root().ID)
}
