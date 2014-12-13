package main

import (
	"fmt"
	"testing"
)

func TestZeroBytes(t *testing.T) {

	var data = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	var clone = append([]byte(nil), data...)
	t.Logf("before: %q", data)
	zeroBytes(data)
	t.Logf("after: %q", data)
	if len(data) != len(clone) {
		t.Fatalf("length changed? before %d, now %d", len(clone), len(data))
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte at index %d not 0, but %d", i, b)
		}
	}
}

func TestZeroString(t *testing.T) {

	// creates a string backed by rw-memory
	var data = fmt.Sprint("1234567890")
	t.Logf("before: %q", data)
	zeroString(&data)
	t.Logf("after: %q", data)
	for i, b := range data {
		if b != 0 {
			t.Fatalf("byte at index %d not 0, but %d", i, b)
		}
	}
}
