package merkletrie

import "testing"

func TestEntriesVisitsEveryEntryAndCanStop(t *testing.T) {
	t.Parallel()
	codec, err := NewCodec(StringEncoding(), Uint64Encoding())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := New[string, uint64](codec)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range []string{"alpha", "beta", "gamma"} {
		tree, _, err = tree.Put(key, uint64(i+1))
		if err != nil {
			t.Fatal(err)
		}
	}
	got := make(map[string]uint64)
	for entry, err := range tree.Entries() {
		if err != nil {
			t.Fatal(err)
		}
		got[entry.Key] = entry.Value
	}
	if len(got) != 3 || got["alpha"] != 1 || got["beta"] != 2 || got["gamma"] != 3 {
		t.Fatalf("entries=%v", got)
	}

	visited := 0
	for range tree.Entries() {
		visited++
		break
	}
	if visited != 1 {
		t.Fatalf("visited=%d", visited)
	}
}
