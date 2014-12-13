package main

import (
	"crypto/sha512"
	"hash"
)

const _SHA512_SIZE_B64 = 88 // = base64.StdEncoding.EncodedLen(sha512.Size)

// read ./sgp_md5.go to read more about the way the buffer works.
type SGPSha512 struct {
	sha512 *NonleakySha512
	buf    [_SHA512_SIZE_B64]byte
}

func (s *SGPSha512) Hasher() hash.Hash { return s.sha512 }
func (s *SGPSha512) MaxLength() int    { return _SHA512_SIZE_B64 }
func (s *SGPSha512) PwBuf() []byte     { return s.buf[:] }
func (s *SGPSha512) HashBuf() []byte   { return s.buf[_SHA512_SIZE_B64-sha512.Size:] }

// observation: for a 64byte (sha512.Size) input the output
// of base64(input) is always 88 bytes AND the last 2 bytes
// are padding ('=')
func (s *SGPSha512) FixPadding(out []byte) {
	out[_SHA512_SIZE_B64-2] = 'A'
	out[_SHA512_SIZE_B64-1] = 'A'
}

func (s *SGPSha512) ZeroBytes() {
	s.sha512.Reset()
	zeroBytes(s.buf[:])
}
