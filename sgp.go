package main

const (
	WASH_ROUNDS         = 10
	MIN_PASSWORD_LENGTH = 4
)

type SGP interface {
	MaxLength() int
	Generate(out []byte, pw_parts ...[]byte)
	ZeroBytes()
	PwBufSize() int
	PwBuf() []byte   // used by generatePass
	HashBuf() []byte // used by Generate()
}

func SupergenPass(out []byte, hasher SGP, password, domain []byte) (err error) {
	return generatePass(out, hasher, password, []byte(":"), domain)
}

func generatePass(out []byte, hasher SGP, pw_parts ...[]byte) (err error) {

	if len(out) > hasher.MaxLength() {
		return errorRequestTooLong(len(out), hasher.MaxLength())
	}

	pw := hasher.PwBuf()
	hasher.Generate(pw, pw_parts...)
	for round := 1; round < WASH_ROUNDS; round += 1 {
		hasher.Generate(pw, pw)
	}

	for !passwordIsValid(pw[:len(out)]) {
		hasher.Generate(pw, pw)
	}

	copy(out, pw)
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

// returns true only if:
//
// 1. 'password' must start with a lowercase letter [a-z].
// 2. 'password' must contain at least one uppercase letter [A-Z].
// 3. 'password' must contain at least one numeral [0-9].
//
// see 'var validatePassword = function (str, length) { ... }' in
// github.com/chriszarate/supergenpass-lib/blob/master/supergenpass-lib.js
func passwordIsValid(password []byte) bool {

	if len(password) == 0 {
		return false
	}

	if !(password[0] >= 'a' && password[0] <= 'z') {
		return false
	}

	var has_digit, has_LETTER bool

	for i := 0; !(has_digit && has_LETTER) && i < len(password); i++ {
		c := password[i]
		if c >= '0' && c <= '9' {
			has_digit = true
		} else if c >= 'A' && c <= 'Z' {
			has_LETTER = true
		}
	}

	return (has_digit && has_LETTER)
}
