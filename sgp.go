package main

import "regexp"

const (
	VALID_PASSWORD_RE = "^[a-z][a-zA-Z0-9]*(?:(?:[A-Z][a-zA-Z0-9]*[0-9])|(?:[0-9][a-zA-Z0-9]*[A-Z]))[a-zA-Z0-9]*$"
	WASH_ROUNDS       = 10
)

var (
	valid_password *regexp.Regexp
)

type SGP interface {
	MaxLength() int
	Generate(out []byte, pw_parts ...[]byte)
	ZeroBytes()      // zero contents of HashBuf() and WorkBuf*()
	HashBuf() []byte // used by HashPassword
	WorkBufSize() int
	WorkBuf1() []byte // used by generatePass
	WorkBuf2() []byte //
}

func init() {
	var err error
	if valid_password, err = regexp.Compile(VALID_PASSWORD_RE); err != nil {
		panic(err)
	}
}

func SupergenPass(out []byte, hasher SGP, password, domain []byte) (err error) {
	return generatePass(out, hasher, password, []byte(":"), domain)
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

	// check and wash until hash is valid
	for !valid_password.Match(buffer[:len(out)]) {
		hasher.Generate(buffer2, buffer)
		buffer, buffer2 = buffer2, buffer
	}

	copy(out, buffer)
	return
}

// see 'var customBase64 = function (str) { ... } ' in
// github.com/chriszarate/supergenpass-lib/blob/master/supergenpass-lib.js
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
