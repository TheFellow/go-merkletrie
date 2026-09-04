// Package merkletrie implements an immutable, content-addressed radix trie.
//
// Keys and values are application-defined. A Codec supplies their canonical
// byte representation; the trie detaches those bytes and uses them for all
// subsequent equality, routing, and persistence operations.
package merkletrie
