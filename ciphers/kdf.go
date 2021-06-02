package ciphers

import "crypto/md5"

// from https://github.com/shadowsocks/go-shadowsocks2/blob/ef4b562095a69750509f82d3f82fc8e6dad50c6e/core/cipher.go
// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
