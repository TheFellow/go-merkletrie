// Command custom-codec demonstrates a canonical encoding for an application type.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/TheFellow/go-merkletrie"
)

type profile struct {
	Name   string   `json:"name"`
	Active bool     `json:"active"`
	Tags   []string `json:"tags"`
}

func main() {
	// This ID is part of the persisted format. Change it whenever the meaning
	// or byte representation of profile changes.
	profileEncoding, err := merkletrie.NewEncoding(
		sha256.Sum256([]byte("example/profile-json/v1")),
		func(value profile) ([]byte, error) { return json.Marshal(value) },
		decodeProfile,
	)
	if err != nil {
		log.Fatal(err)
	}
	codec, err := merkletrie.NewCodec(merkletrie.StringEncoding(), profileEncoding)
	if err != nil {
		log.Fatal(err)
	}
	tree, err := merkletrie.New(codec, merkletrie.WithNamespace([]byte("accounts")))
	if err != nil {
		log.Fatal(err)
	}
	tree, _, err = tree.Put("ada", profile{Name: "Ada", Active: true, Tags: []string{"admin", "early-user"}})
	if err != nil {
		log.Fatal(err)
	}

	value, found, err := tree.Lookup("ada")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("found=%v name=%s tags=%v\n", found, value.Name, value.Tags)
}

func decodeProfile(encoded []byte) (profile, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value profile
	if err := decoder.Decode(&value); err != nil {
		return profile{}, err
	}
	if err := expectEOF(decoder); err != nil {
		return profile{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return profile{}, err
	}
	if !bytes.Equal(canonical, encoded) {
		return profile{}, fmt.Errorf("non-canonical profile encoding")
	}
	return value, nil
}

func expectEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
