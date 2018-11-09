package main

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"
)

func exit(code int, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err.Error())
	}
	os.Exit(code)
}

func errorRequestTooLong(in, max int) error {
	return fmt.Errorf("requested password too long (%d, max %d)",
		in, max)
}

func errorRequestTooShort(in, min int) error {
	return fmt.Errorf("requested password too short (%d, min %d)",
		in, min)
}

func zeroBytes(data ...[]byte) {
	for i := range data {
		for j := range data[i] {
			data[i][j] = 0
		}
	}
}

// zero the underlying storage of a string.
//
// NOTE: this is an unsafe operation! which only works if
// 's' is a string backed by rw-memory (heap, stack)
// and not by memory in the (ro-only) text-segment. eg,
// this function will panic on const a = "foo"
//
// NOTE2: since all of this is an unsafe operation we do not
// hand back the helper byte-slice.
func zeroString(s *string) {
	header := (*reflect.StringHeader)(unsafe.Pointer(s))
	bufHeader := reflect.SliceHeader{Data: header.Data, Len: header.Len, Cap: header.Len}
	buf := (*[]byte)(unsafe.Pointer(&bufHeader))
	zeroBytes(*buf)
}
