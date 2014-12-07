package main

import (
	"crypto/sha512"
	"encoding/base64"
)

const _SHA512_SIZE_B64 = 88 // = base64.StdEncoding.EncodedLen(sha512.Size)

type SGPSha512 struct {
	sha512 *NonleakySha512
	buf    [(2 * _SHA512_SIZE_B64) + sha512.Size]byte
}

func (s *SGPSha512) MaxLength() int   { return base64.StdEncoding.EncodedLen(sha512.Size) }
func (s *SGPSha512) WorkBufSize() int { return base64.StdEncoding.EncodedLen(sha512.Size) }
func (s *SGPSha512) HashBuf() []byte  { return s.buf[2*s.WorkBufSize():] }
func (s *SGPSha512) WorkBuf1() []byte { return s.buf[:s.WorkBufSize()] }
func (s *SGPSha512) WorkBuf2() []byte { return s.buf[s.WorkBufSize() : 2*s.WorkBufSize()] }

func (s *SGPSha512) Generate(out []byte, pw_parts ...[]byte) {

	hash := s.HashBuf()

	defer s.sha512.Reset()
	defer zeroBytes(hash)

	s.sha512.Reset()
	for i := range pw_parts {
		s.sha512.Write(pw_parts[i])
	}
	s.sha512.Sum(hash)

	base64.StdEncoding.Encode(out, hash)
	replaceLikeSupergenpass(out)
}

func (s *SGPSha512) ZeroBytes() {
	s.sha512.Reset()
	zeroBytes(s.buf[:])
}
