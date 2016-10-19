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
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh/terminal"
)

const ABOUT = "gosgp - repeatable password generator (golang-port of supergenpass.com)"

func main() {

	var (
		opts = struct {
			domain      string
			length      int
			lock_memory bool
			sha         bool
		}{length: 10, lock_memory: true}
		password, domain, generated []byte
		sgp_md5                         = SGPMd5{md5: NewNonleakyMd5()}
		sgp_sha512                      = SGPSha512{sha512: NewNonleakySha512()}
		hasher                      SGP = &sgp_md5
		err                         error
	)

	flag.StringVar(&opts.domain, "domain", opts.domain, "domain")
	flag.IntVar(&opts.length, "length", opts.length, "length")
	flag.BoolVar(&opts.sha, "sha", opts.sha, "use sha512 instead of md5")
	flag.BoolVar(&opts.lock_memory, "lock", opts.lock_memory, "lock memory")
	flag.Usage = usage
	flag.Parse()

	if opts.lock_memory {
		lockMemory()
	}

	if opts.sha {
		hasher = &sgp_sha512
	}

	defer hasher.ZeroBytes()

	if opts.length > hasher.MaxLength() {
		exit(1, errorRequestTooLong(opts.length, hasher.MaxLength()))
	}
	if opts.length < MIN_PASSWORD_LENGTH {
		exit(1, errorRequestTooShort(opts.length, MIN_PASSWORD_LENGTH))
	}

	if opts.domain == "" {
		if len(flag.Args()) > 0 {
			opts.domain = flag.Arg(0)
		} else {
			fmt.Print("  domain: ")
			fmt.Scanf("%s", &opts.domain)
		}
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

	err = SupergenPass(generated, hasher, password, domain)
	hasher.ZeroBytes()
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

func usage() {
	fmt.Fprintln(os.Stderr, ABOUT, fmt.Sprintf("usage of %s:\n", os.Args[0]))
	flag.PrintDefaults()
}
