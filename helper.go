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

func errorRequestToBig(in, max int) error {
	return fmt.Errorf("requested password to long (%d, max %d)",
		in, max)
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
	buf_header := reflect.SliceHeader{Data: header.Data, Len: header.Len, Cap: header.Len}
	buf := (*[]byte)(unsafe.Pointer(&buf_header))
	zeroBytes(*buf)
}
