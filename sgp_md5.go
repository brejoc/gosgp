package main

import (
	"crypto/md5"
	"encoding/base64"
	"hash"
)

const _MD5_SIZE_B64 = 24 // = base64.StdEncoding.EncodedLen(md5.Size)

type SGPMd5 struct {
	md5 *NonleakyMd5
	buf [_MD5_SIZE_B64 + md5.Size]byte
}

func (s *SGPMd5) Hasher() hash.Hash { return s.md5 }
func (s *SGPMd5) MaxLength() int    { return base64.StdEncoding.EncodedLen(md5.Size) }
func (s *SGPMd5) PwBufSize() int    { return base64.StdEncoding.EncodedLen(md5.Size) }
func (s *SGPMd5) PwBuf() []byte     { return s.buf[:s.PwBufSize()] }
func (s *SGPMd5) HashBuf() []byte   { return s.buf[s.PwBufSize():] }

// observation: for a 16byte (md5.Size) input the output
// of base64(input) is always 24 bytes AND the last 2 bytes
// are padding ('=')
func (s *SGPMd5) FixPadding(out []byte) {
	out[_MD5_SIZE_B64-2] = 'A'
	out[_MD5_SIZE_B64-1] = 'A'
}

func (s *SGPMd5) ZeroBytes() {
	s.md5.Reset()
	zeroBytes(s.buf[:])
}
