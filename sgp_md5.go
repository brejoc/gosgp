package main

import (
	"crypto/md5"
	"encoding/base64"
)

const _MD5_SIZE_B64 = 24 // = base64.StdEncoding.EncodedLen(md5.Size)

type SGPMd5 struct {
	md5 *NonleakyMd5
	buf [_MD5_SIZE_B64 + md5.Size]byte
}

func (s *SGPMd5) MaxLength() int  { return base64.StdEncoding.EncodedLen(md5.Size) }
func (s *SGPMd5) PwBufSize() int  { return base64.StdEncoding.EncodedLen(md5.Size) }
func (s *SGPMd5) PwBuf() []byte   { return s.buf[:s.PwBufSize()] }
func (s *SGPMd5) HashBuf() []byte { return s.buf[s.PwBufSize():] }

func (s *SGPMd5) Generate(out []byte, pw_parts ...[]byte) {

	hash := s.HashBuf()

	defer s.md5.Reset()
	defer zeroBytes(hash)

	s.md5.Reset()
	for i := range pw_parts {
		s.md5.Write(pw_parts[i])
	}
	s.md5.Sum(hash)

	base64.StdEncoding.Encode(out, hash)
	replaceLikeSupergenpass(out)
}

func (s *SGPMd5) ZeroBytes() {
	s.md5.Reset()
	zeroBytes(s.buf[:])
}
