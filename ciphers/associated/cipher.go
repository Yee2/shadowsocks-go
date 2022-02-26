package associated

import (
	"crypto/cipher"
)

type Cipher interface {
	Name() string
	KeySize() int
	SaltSize() int
	NonceSize() int
	TagSize() int
	New(key []byte) (cipher.AEAD, error)
}
