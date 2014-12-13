package main

import (
	"crypto/sha512"
	"hash"
	"reflect"
	"unsafe"
)

// sha512-variant, see md5.go to read more about the reason
// to reimplement sha512.

var _SHA512_PADDING [128]byte // read-only block, only purpose: padding

func init() {
	_SHA512_PADDING[0] = 0x80

	nlsha512 := NewNonleakySha512()
	nlsha512.field_h()
	nlsha512.field_x()
	nlsha512.field_nx()
	nlsha512.field_len()
}

type NonleakySha512 struct {
	hash.Hash
	hash_value reflect.Value
}

// shared functions with crypto.sha1

func (d *NonleakySha512) Write(p []byte) (int, error) { return d.Hash.Write(p) }
func (d *NonleakySha512) Size() int                   { return d.Hash.Size() }
func (d *NonleakySha512) BlockSize() int              { return d.Hash.BlockSize() }

// specialized functions

func NewNonleakySha512() *NonleakySha512 {
	hash := sha512.New()
	return &NonleakySha512{Hash: hash, hash_value: reflect.ValueOf(hash)}
}

// resets the hasher to the initial state and zero all buffers
func (d *NonleakySha512) Reset() {
	d.Hash.Reset()
	zeroBytes(d.field_x()[:])
}

func (d *NonleakySha512) field_h() *[8]uint64 {
	return (*[8]uint64)(unsafe.Pointer(d.hash_value.Elem().Field(0).Addr().Pointer()))
}

func (d *NonleakySha512) field_x() *[128]byte {
	return (*[128]byte)(unsafe.Pointer(d.hash_value.Elem().Field(1).Addr().Pointer()))
}

func (d *NonleakySha512) field_nx() int64 {
	return d.hash_value.Elem().Field(2).Int()
}

func (d *NonleakySha512) field_len() uint64 {
	return d.hash_value.Elem().Field(3).Uint()
}

// almost 1:1 copy of sha1.New().Sum(), except that
// it expects the provided buffer to be at least
// d.Size bytes big
func (d *NonleakySha512) Sum(digest []byte) []byte {

	if len(digest) < d.Size() {
		panic("digest parameter is not big enough")
	}

	len := d.field_len()
	if len%128 < 112 {
		d.Write(_SHA512_PADDING[0 : 112-len%128])
	} else {
		d.Write(_SHA512_PADDING[0 : 128+112-len%128])
	}

	// Length in bits.
	var tmp [16]byte
	len <<= 3
	for i := uint(0); i < 16; i++ {
		tmp[i] = byte(len >> (120 - 8*i))
	}
	d.Write(tmp[:])
	zeroBytes(tmp[:])

	if d.field_nx() != 0 {
		panic("d.nx != 0")
	}

	for i, h := range d.field_h() {
		i *= 8
		digest[i] = byte(h >> 56)
		digest[i+1] = byte(h >> 48)
		digest[i+2] = byte(h >> 40)
		digest[i+3] = byte(h >> 32)
		digest[i+4] = byte(h >> 24)
		digest[i+5] = byte(h >> 16)
		digest[i+6] = byte(h >> 8)
		digest[i+7] = byte(h)
	}

	return digest
}
