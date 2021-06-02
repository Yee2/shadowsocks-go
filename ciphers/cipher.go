package ciphers

import (
	"crypto/cipher"
	"errors"
)

var AlreadyRegistered = errors.New("already registered")
var CipherNotSupported = errors.New("cipher not supported")

type StreamCipher interface {
	Name() string
	IVLength() int
	KeySize() int
	Cipher(key []byte) (cipher.Block, error)
	Decryptor(block cipher.Block, iv []byte) cipher.Stream
	Encryptor(block cipher.Block, iv []byte) cipher.Stream
}

type AEADCipher interface {
	Name() string
	KeySize() int
	SaltSize() int
	NonceSize() int
	TagSize() int
	NewAEAD(key []byte) (cipher.AEAD, error)
}
