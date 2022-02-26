package associated

import (
	"crypto/cipher"
	"golang.org/x/crypto/chacha20poly1305"
)

type chacha20 struct{}

func (*chacha20) Name() string {
	return "chacha20-ietf-poly1305"
}

func (*chacha20) KeySize() int {
	return chacha20poly1305.KeySize
}

func (*chacha20) NonceSize() int {
	return chacha20poly1305.NonceSize
}

func (*chacha20) SaltSize() int {
	return 32
}
func (*chacha20) TagSize() int {
	return 16
}

func (*chacha20) New(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
