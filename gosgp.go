/*
   gosgp is a command line tool to generate SuperGenPass passwords
   for a given domain. gosgp won't trim the relevant parts from you
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

package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"regexp"
	"strings"

	"code.google.com/p/go.crypto/ssh/terminal"
)

func main() {
	var password string
	var domain string
	fmt.Print("domain: ")
	fmt.Scanf("%s", &domain)
	fmt.Print("password: ")
	pwd_buff, err := terminal.ReadPassword(0)
	if err != nil {
		panic(err)
	}
	password = string(pwd_buff)
	fmt.Println(Generate(password, domain, 10))
}

func Generate(master, domain string, length int) string {
	// regex to check the password
	validPassword, err := regexp.Compile("^[a-z][a-zA-Z0-9]*(?:(?:[A-Z][a-zA-Z0-9]*[0-9])|(?:[0-9][a-zA-Z0-9]*[A-Z]))[a-zA-Z0-9]*$")
	if err != nil {
		log.Fatal(err)
	}

	password := master + ":" + domain
	pwdHash := password
	count := 0
	// washing the password ten times
	for count < 10 {
		pwdHash = PasswordHash(pwdHash)
		count += 1
	}

	// check and wash until hash ist valid
	for !validPassword.Match([]byte(fmt.Sprintf("%s", pwdHash[:length]))) {
		pwdHash = PasswordHash(pwdHash)
	}

	return pwdHash[:length]
}

func PasswordHash(password string) string {
	// this example only supports md5
	// md5sum
	h := md5.New()
	io.WriteString(h, password)
	// base64
	b64pwd := base64.StdEncoding.EncodeToString([]byte(h.Sum(nil)))
	// Supergenpass specific relacements
	b64pwd = strings.Replace(b64pwd, "=", "A", -1)
	b64pwd = strings.Replace(b64pwd, "/", "8", -1)
	b64pwd = strings.Replace(b64pwd, "+", "9", -1)
	return b64pwd
}
