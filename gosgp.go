package main

/*
   gosgp is a command line tool to generate SuperGenPass passwords
   for a given domain. gosgp won't trim the relevant parts from your
   URL string, so please only use domains.

   Copyright (C) 2014 Jochen Breuer <brejoc@gmail.com>

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; either version 2
   of the License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

import (
	"crypto/md5"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"regexp"

	"code.google.com/p/go.crypto/ssh/terminal"
)

const (
	ABOUT             = "gosgp - repeatable password generator (golang-port of supergenpass.com)"
	VALID_PASSWORD_RE = "^[a-z][a-zA-Z0-9]*(?:(?:[A-Z][a-zA-Z0-9]*[0-9])|(?:[0-9][a-zA-Z0-9]*[A-Z]))[a-zA-Z0-9]*$"
	WASH_ROUNDS       = 10
)

var (
	valid_password *regexp.Regexp
	max_length     = base64.StdEncoding.EncodedLen(md5.Size)
)

func init() {
	var err error
	if valid_password, err = regexp.Compile(VALID_PASSWORD_RE); err != nil {
		panic(err)
	}
}

func main() {

	var (
		opts = struct {
			domain      string
			length      int
			lock_memory bool
		}{length: 10, lock_memory: true}
		password, domain, generated []byte
		hasher                      SGP
		err                         error
	)

	flag.StringVar(&opts.domain, "domain", opts.domain, "domain")
	flag.IntVar(&opts.length, "length", opts.length, "length")
	flag.BoolVar(&opts.lock_memory, "lock", opts.lock_memory, "lock memory")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, ABOUT, fmt.Sprintf("usage of %s:\n", os.Args[0]))
		flag.PrintDefaults()
	}
	flag.Parse()

	if opts.length > max_length {
		exit(1, errorRequestToBig(opts.length, max_length))
	}

	if opts.lock_memory {
		lockMemory()
	}

	if opts.domain == "" {
		fmt.Print("  domain: ")
		fmt.Scanf("%s", &opts.domain)
	}

	fmt.Printf("password: ")
	if password, err = terminal.ReadPassword(int(os.Stdin.Fd())); err != nil {
		exit(1, err)
	}

	// []byte(...) creates a copy of the string-bytes (strings are read-only)
	// so, we have to zero both the string and the copy
	domain = []byte(opts.domain)
	zeroString(&opts.domain)

	generated = make([]byte, opts.length)
	defer zeroBytes(generated)

	hasher = &SGPMd5{md5: NewNonleakyMd5()}
	defer hasher.ZeroBytes()

	err = SupergenPass(generated, hasher, password, domain)
	zeroBytes(password, domain)

	fmt.Println()
	if err != nil {
		exit(2, err)
	}

	// fmt.Printf() might keep (unreachable) data in buffers around
	os.Stdout.Write(generated)
	zeroBytes(generated)
	fmt.Println()
}

func SupergenPass(out []byte, hasher SGP, password, domain []byte) (err error) {
	return generatePass(out, hasher, password, []byte(":"), domain)
}

type SGP interface {
	Generate(out []byte, pw_parts ...[]byte)
	ZeroBytes()      // zero contents of HashBuf() and WorkBuf*()
	HashBuf() []byte // used by HashPassword
	WorkBufSize() int
	WorkBuf1() []byte // used by generatePass
	WorkBuf2() []byte //
}

func generatePass(out []byte, hasher SGP, pw_parts ...[]byte) (err error) {

	if len(out) > hasher.WorkBufSize() {
		return errorRequestToBig(len(out), hasher.WorkBufSize())
	}

	buffer, buffer2 := hasher.WorkBuf1(), hasher.WorkBuf2()

	hasher.Generate(buffer, pw_parts...)
	for round := 1; round < WASH_ROUNDS; round += 1 {
		hasher.Generate(buffer2, buffer)
		buffer, buffer2 = buffer2, buffer
	}

	// check and wash until hash ist valid
	for !valid_password.Match(buffer[:len(out)]) {
		hasher.Generate(buffer2, buffer)
		buffer, buffer2 = buffer2, buffer
	}

	copy(out, buffer)
	return
}

type SGPMd5 struct {
	md5 *NonleakyMd5
	buf [(2 * 24) + md5.Size]byte // 24 = base64.StdEncoding.EncodedLen(md5.Size)
}

func (s *SGPMd5) WorkBufSize() int { return base64.StdEncoding.EncodedLen(md5.Size) }
func (s *SGPMd5) HashBuf() []byte  { return s.buf[2*s.WorkBufSize():] }
func (s *SGPMd5) WorkBuf1() []byte { return s.buf[:s.WorkBufSize()] }
func (s *SGPMd5) WorkBuf2() []byte { return s.buf[s.WorkBufSize() : 2*s.WorkBufSize()] }

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

func replaceLikeSupergenpass(src []byte) {
	for i := range src {
		switch src[i] {
		case '=':
			src[i] = 'A'
		case '/':
			src[i] = '8'
		case '+':
			src[i] = '9'
		}
	}
}
