package main

// we need to be sure how base64.Encode() is implemented to limit the number
// of bytes used. since we can't control it upstream (go-1.3.x is breaking
// our assumption about when and which bytes are written into the destination
// buffer; go-1.4 is ok) we roll our own

// supergenpass uses a special base64-encoding which replaces
// '+' by '9' and '/' by '8'. this is easily done by using
// _SGP_BASE64_ALPHABET. after encoding the hash the padding
// chars must be replaced by '=' signs as well, see SGP.FixPadding()
var _SGP_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678998"

// losely modeled after go-1.4 encoding/base64/base64.go
func sgpBase64(out, in []byte, alphabet string) {

	var b0, b1, b2, b3 byte

	for len(in) > 0 {
		switch len(in) {
		default:
			b3 = in[2] & 0x3f
			b2 = in[2] >> 6
			fallthrough
		case 2:
			b2 |= (in[1] << 2) & 0x3f
			b1 = in[1] >> 4
			fallthrough
		case 1:
			b1 |= (in[0] << 4) & 0x3f
			b0 = in[0] >> 2
		}

		out[0] = alphabet[b0]
		out[1] = alphabet[b1]

		if len(in) >= 3 { // new round needed
			out[2] = alphabet[b2]
			out[3] = alphabet[b3]
		} else {
			if len(in) >= 2 {
				out[2] = alphabet[b2]
			} else {
				out[2] = '='
			}
			out[3] = '='

			b0, b1, b2, b3 = 0, 0, 0, 0
			break
		}

		b0, b1, b2, b3 = 0, 0, 0, 0
		in = in[3:]
		out = out[4:]
	}
}
