package merkletrie

import "testing"

func FuzzDecodeObject(f *testing.F) {
	codec, err := NewCodec(StringEncoding(), BytesEncoding())
	if err != nil {
		f.Fatal(err)
	}
	tree, err := New[string, []byte](codec)
	if err != nil {
		f.Fatal(err)
	}
	tree, _, err = tree.Put("seed", []byte("value"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(tree.Objects()[0].Payload)
	f.Add([]byte("not an object"))

	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _ = DecodeObject[string, []byte](codec, payload, Digest{})
	})
}
