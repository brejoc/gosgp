package main

import (
	"crypto/md5"
	"hash"
)

const _MD5_SIZE_B64 = 24 // = base64.StdEncoding.EncodedLen(md5.Size)

//
// while optimizing csgp ( https://github.com/mgumz/csgp ) i realized
// that the needed buffer-size is actually quite small:
// 1. we need 16bytes to store the raw md5-digest
// 2. we need 24bytes to store the base64 encoded md5-digest
// 3. it's sufficient to store the raw md5-digest inside
//    the base64-buffer, like this: [24......[16..............]]
//
//  this works because:
//  * the master-passwords ends up directly as a md5-state in the first
//    round
//  * the md5-state is copied over into the 16byte block
//  * the 16byte block gets base64-encoded. the b64-encoder chases the
//     currently processed byte from the 16byte block but never catches
//     up; except for the last round. in that round, any trace of the raw
//     md5-state got erased by the base64-version of it:
//           +--------+
//       [aaaa.......[111.........]]
//       [aaaabbbb...[111222......]]
//       [aaaabbbbccc[c11222333...]]
//
//  * the 24byte buffer is then transformed into a md5-state and
//    the whole process repeats.
//
//  the same principle applies to sgp_sha512.go

type SGPMd5 struct {
	md5 *NonleakyMd5
	buf [_MD5_SIZE_B64]byte
}

func (s *SGPMd5) Hasher() hash.Hash { return s.md5 }
func (s *SGPMd5) MaxLength() int    { return _MD5_SIZE_B64 }
func (s *SGPMd5) PwBuf() []byte     { return s.buf[:] }
func (s *SGPMd5) HashBuf() []byte   { return s.buf[_MD5_SIZE_B64-md5.Size:] }

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
