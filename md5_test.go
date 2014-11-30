package main

import (
	"bytes"
	"crypto/md5"
	"reflect"
	"testing"
)

func TestNonleakyMd5(t *testing.T) {

	var (
		data     = []byte("gopher gopher gopher")
		orig     = md5.Sum(data)
		nlmd5    = NewNonleakyMd5()
		nonleaky = make([]byte, nlmd5.Size())
	)

	nlmd5.Write(data)
	nlmd5.Sum(nonleaky)

	t.Logf("expected %x, got %x", orig, nonleaky)

	if !bytes.Equal(nonleaky, orig[:]) {
		t.Fatalf("mismatch between crypt.md5.Sum() and NonleakyMd5.Sum()")
	}

	t.Logf("before nlmd5.Reset():\n%v", nlmd5.hash_value.Interface())
	nlmd5.Reset()
	t.Logf("after nlmd5.Reset():\n%v", nlmd5.hash_value.Interface())

	for _, b := range nlmd5.field_x() {
		if b != 0 {
			t.Fatal("NonleakyMd5.raw.x not correctly cleaned")
		}
	}

	for _, b := range nlmd5.tmp {
		if b != 0 {
			t.Fatal("NonleakyMd5.tmp not correctly cleaned")
		}
	}

	if !reflect.DeepEqual(nlmd5.Hash, md5.New()) {
		t.Fatal("reflect.DeepEqual complaints about nlmd5.Hash != md5.New()")
	}

}
