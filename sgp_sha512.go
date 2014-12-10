package main

import (
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

const _SHA512_SIZE_B64 = 88 // = base64.StdEncoding.EncodedLen(sha512.Size)

type SGPSha512 struct {
	sha512 *NonleakySha512
	buf    [_SHA512_SIZE_B64 + sha512.Size]byte
}

func (s *SGPSha512) Hasher() hash.Hash { return s.sha512 }
func (s *SGPSha512) MaxLength() int    { return base64.StdEncoding.EncodedLen(sha512.Size) }
func (s *SGPSha512) PwBufSize() int    { return base64.StdEncoding.EncodedLen(sha512.Size) }
func (s *SGPSha512) PwBuf() []byte     { return s.buf[:s.PwBufSize()] }
func (s *SGPSha512) HashBuf() []byte   { return s.buf[s.PwBufSize():] }

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
