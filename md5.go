package main

import (
	"crypto/md5"
	"hash"
	"reflect"
	"unsafe"
)

// why is a special implementation of crypt.md5 needed? because
// currently there is no way of getting a hold on either the
// digest-copy in md5.New().Sum() or on the created digest in
// md5.Sum() or on the tmp-buffer in md5.checkSum(). in order
// to avoid reimplementing everything i opted to use reflect
// and a little helper to modify only minor aspects of md5.checkSum.
//
// NonleakyMd5.Reset() ensures the nonleaky nature
//
// worth reading: http://blog.golang.org/laws-of-reflection

func init() {
	// create a temporary NonleakyMd5 and access the internal
	// fields. if something in the implementation changed
	// dramatically, the NonleakyMd5.field_* functions should
	// panic.
	nlmd5 := NewNonleakyMd5()
	nlmd5.field_s()
	nlmd5.field_x()
	nlmd5.field_nx()
	nlmd5.field_len()
}

type NonleakyMd5 struct {
	hash.Hash
	hash_value reflect.Value
	tmp        [64]byte
}

// shared functions with crypto.md5

func (d *NonleakyMd5) Write(p []byte) (int, error) { return d.Hash.Write(p) }
func (d *NonleakyMd5) Size() int                   { return d.Hash.Size() }
func (d *NonleakyMd5) BlockSize() int              { return d.Hash.BlockSize() }

// specialized functions

func NewNonleakyMd5() *NonleakyMd5 {
	hash := md5.New()
	return &NonleakyMd5{Hash: hash, hash_value: reflect.ValueOf(hash)}
}

// resets the hasher to the initial state and zero all buffers
func (d *NonleakyMd5) Reset() {
	d.Hash.Reset()
	zeroBytes(d.field_x()[:])
	zeroBytes(d.tmp[:])
}

func (d *NonleakyMd5) field_s() *[4]uint32 {
	return (*[4]uint32)(unsafe.Pointer(d.hash_value.Elem().Field(0).Addr().Pointer()))
}

func (d *NonleakyMd5) field_x() *[64]byte {
	return (*[64]byte)(unsafe.Pointer(d.hash_value.Elem().Field(1).Addr().Pointer()))
}

func (d *NonleakyMd5) field_nx() int64 {
	return d.hash_value.Elem().Field(2).Int()
}

func (d *NonleakyMd5) field_len() uint64 {
	return d.hash_value.Elem().Field(3).Uint()
}

// almost 1:1 copy of md5.New().Sum(), except that
// it expects the provided buffer to be at least
// d.Size bytes big
func (d *NonleakyMd5) Sum(digest []byte) []byte {

	if len(digest) < d.Size() {
		panic("digest parameter is not big enough")
	}

	len := d.field_len()
	d.tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(d.tmp[0 : 56-len%64])
	} else {
		d.Write(d.tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		d.tmp[i] = byte(len >> (8 * i))
	}
	d.Write(d.tmp[0:8])

	if d.field_nx() != 0 {
		panic("d.nx != 0")
	}

	for i, s := range d.field_s() {
		i *= 4
		digest[i] = byte(s)
		digest[i+1] = byte(s >> 8)
		digest[i+2] = byte(s >> 16)
		digest[i+3] = byte(s >> 24)
	}

	return digest
}
