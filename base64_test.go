package main

import (
	"bytes"
	"testing"
)

func TestBase64(t *testing.T) {
	var samples = []struct {
		in, out string
	}{
		{"", ""},
		{"1", "MQ=="},
		{"12", "MTI="},
		{"123", "MTIz"},
		{"1234", "MTIzNA=="},
		{"12345", "MTIzNDU="},
		{"123456", "MTIzNDU2"},
	}

	t.Log("test non-overlapping buffers")
	for i, sample := range samples {
		in := []byte(sample.in)
		expected := []byte(sample.out)
		out := make([]byte, len(expected))

		sgpBase64(out, in, _SGP_BASE64_ALPHABET)

		t.Logf("%d: %q => %q", i, in, out)

		if bytes.Compare(out, expected) != 0 {
			t.Fatalf("%d: expected %q for %q, got %q", i, expected, in, out)
		}
	}

	// test-case for
	// [bbbb....[xxxyyy]]
	//  +--------+
	t.Log("test selfencoding-buffer")
	for i, sample := range samples {
		expected := []byte(sample.out)
		out := make([]byte, len(expected))
		j := len(out) - len(sample.in)
		copy(out[j:], sample.in)

		sgpBase64(out, out[j:], _SGP_BASE64_ALPHABET)

		t.Logf("%d: %q => %q", i, sample.in, out)

		if bytes.Compare(out, expected) != 0 {
			t.Fatalf("%d: expected %q for %q, got %q", i, expected, sample.in, out)
		}
	}

}
