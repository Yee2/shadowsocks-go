package associated

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

var AES128GCM = New(&aesgcm{keySize: 16, saltSize: 16})
var AES192GCM = New(&aesgcm{keySize: 24, saltSize: 24})
var AES256GCM = New(&aesgcm{keySize: 32, saltSize: 32})
var Chacha20IetfPoly1305 = New(&chacha20{})

type aesgcm struct {
	keySize,
	saltSize,
	nonceSize,
	tagSize int
}

func (c *aesgcm) Name() string {
	switch c.keySize {
	case 16, 24, 32:
	default:
		panic("error")
	}
	switch c.saltSize {
	case 16, 24, 32:
	default:
		panic("error")
	}
	return fmt.Sprintf("aes-%d-gcm", c.keySize*8)
}

func (c *aesgcm) KeySize() int {
	return c.keySize
}
func (c *aesgcm) SaltSize() int {
	return c.saltSize
}
func (c *aesgcm) NonceSize() int {
	return 12
}
func (c *aesgcm) TagSize() int {
	return 16
}
func (c *aesgcm) New(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
