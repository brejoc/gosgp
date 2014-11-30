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

	err = SupergenPass(generated, password, domain)
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

func SupergenPass(out []byte, password, domain []byte) (err error) {
	return generatePass(out, password, []byte(":"), domain)
}

func generatePass(out []byte, seed_parts ...[]byte) (err error) {

	// after the first round we operate only on 2 buffers of
	// size base64(md5(input)). to avoid spreading data all over
	// the heap we just allocate one bigger buffer and hand out
	// subslices to it to 'password', 'buffer' and 'buffer2'
	var (
		nbytes_seed = countBytes(seed_parts...)
		nbytes_buf  = base64.StdEncoding.EncodedLen(md5.Size)
		storage     = make([]byte, nbytes_seed+2*nbytes_buf)
		seed        = storage[:nbytes_seed]
		buffer      = storage[len(seed) : len(seed)+nbytes_buf]
		buffer2     = storage[len(seed)+nbytes_buf:]
	)

	if len(out) > nbytes_buf {
		return errorRequestToBig(len(out), nbytes_buf)
	}

	defer zeroBytes(storage)
	concatBytesInto(seed, seed_parts...)

	// initial wash of the password
	// seed is used to get the rounds going and after that
	// only buffer and buffer2 are used
	hashPassword(buffer, seed)
	for round := 1; round < WASH_ROUNDS; round += 1 {
		hashPassword(buffer2, buffer)
		buffer, buffer2 = buffer2, buffer
	}

	// check and wash until hash ist valid
	for !valid_password.Match(buffer[:len(out)]) {
		hashPassword(buffer2, buffer)
		buffer, buffer2 = buffer2, buffer
	}

	copy(out, buffer)
	return
}

// pipes 'password' through md5 and base64 it afterwards
// into 'b64_hash' (which must be at least
// base64.StdEncoding.EncodedLen(len(password)) bytes big)
func hashPassword(b64_hash, password []byte) {

	// h := md5.New(); h.Write(password); h.Sum() leaks
	// the password: it allocates an unreachable copy of
	// itself when calling h.Sum()
	h := md5.Sum(password)
	hash := h[:]
	defer zeroBytes(hash)

	base64.StdEncoding.Encode(b64_hash, hash)
	replaceLikeSupergenpass(b64_hash)
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
