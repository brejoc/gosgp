package main

import (
	"bytes"
	"testing"
)

func TestSupergenPass(t *testing.T) {

	// samples to match against, created via
	// https://chriszarate.github.io/supergenpass/mobile/
	var samples = []struct{ domain, pw, supergenpass string }{
		{"example.com", "1", "dlHhFkN3vr"},
		{"example.com", "123", "mhn91FJ7Ug"},
		{"github.io", "mypassword123", "cCB9oTktwn"},
	}

	for i, sample := range samples {
		pw := make([]byte, len(sample.supergenpass))
		err := SupergenPass(pw, []byte(sample.pw), []byte(sample.domain))
		t.Logf("%d supergenpass(%q,%q) = %q", i, sample.pw, sample.domain, pw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pw, []byte(sample.supergenpass)) {
			t.Fatalf("sample %d: expected %q (domain: %q, pw: %q), got %q",
				i, sample.supergenpass, sample.domain, sample.pw, pw)
		}
	}
}
