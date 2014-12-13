package main

import (
	"bytes"
	"crypto/sha512"
	"reflect"
	"testing"
)

func TestNonleakySha512(t *testing.T) {

	var (
		data     = []byte("gopher gopher gopher")
		orig     = sha512.Sum512(data)
		nlsha512 = NewNonleakySha512()
		nonleaky = make([]byte, nlsha512.Size())
	)

	nlsha512.Write(data)
	nlsha512.Sum(nonleaky)

	t.Logf("expected %x", orig)
	t.Logf("     got %x", nonleaky)

	if !bytes.Equal(nonleaky, orig[:]) {
		t.Fatalf("mismatch between crypt.sha512.Sum() and NonleakySha512.Sum()")
	}

	t.Logf("before nlsha512.Reset():\n%v", nlsha512.hash_value.Interface())
	nlsha512.Reset()
	t.Logf("after nlsha512.Reset():\n%v", nlsha512.hash_value.Interface())

	for _, b := range nlsha512.field_x() {
		if b != 0 {
			t.Fatal("NonleakySha512.raw.x not correctly cleaned")
		}
	}

	for _, b := range _SHA512_PADDING[1:] {
		if b != 0 {
			t.Fatal("NonleakySha512._SHA512_PADDING unclean")
		}
	}

	if !reflect.DeepEqual(nlsha512.Hash, sha512.New()) {
		t.Fatal("reflect.DeepEqual complaints about nlsha512.Hash != sha512.New()")
	}

}
