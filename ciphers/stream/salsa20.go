package stream

import (
	"crypto/cipher"
	"fmt"
	"golang.org/x/crypto/salsa20/salsa"
)

var Salsa20 = NewStream(&salsa20Cipher{})
var runtimeError = fmt.Errorf("system error")

// salsa20 加密方式，参考 salsa20/salsa/salsa20_ref.go
// nonce 后 8 位作为计数器，前 8 位为 IV
type salsaStreamCipher struct {
	key   [32]byte
	nonce [16]byte
}

func newSalsa20(key []byte, iv []byte) cipher.Stream {
	s := new(salsaStreamCipher)
	copy(s.key[:], key)
	copy(s.nonce[:8], iv)
	return s
}
func (s *salsaStreamCipher) increase(u uint32) {
	for i := 8; i < 16; i++ {
		u += uint32(s.nonce[i])
		s.nonce[i] = byte(u)
		u >>= 8
	}
}
func (s *salsaStreamCipher) XORKeyStream(dst, src []byte) {
	blocks := len(src) / 64
	if len(src)%64 > 0 {
		blocks++
	}
	salsa.XORKeyStream(dst, src, &s.nonce, &s.key)
	s.increase(uint32(blocks))
}

type salsa20Cipher struct {
}

func (c *salsa20Cipher) Name() string {
	return "salsa20"
}

func (c *salsa20Cipher) IVLength() int {
	return 8
}

func (c *salsa20Cipher) KeySize() int {
	return 32
}
func (c *salsa20Cipher) Cipher(key []byte) (cipher.Block, error) {
	return &salsa20Block{key: key}, nil
}

func (c *salsa20Cipher) Decryptor(block cipher.Block, iv []byte) cipher.Stream {
	key, ok := block.(*salsa20Block)
	if !ok {
		panic(runtimeError)
	}
	return newSalsa20(key.key, iv)
}

func (c *salsa20Cipher) Encryptor(block cipher.Block, iv []byte) cipher.Stream {
	key, ok := block.(*salsa20Block)
	if !ok {
		panic(runtimeError)
	}
	return newSalsa20(key.key, iv)
}

type salsa20Block struct {
	key []byte
}

func (c *salsa20Block) BlockSize() int {
	return 64
}

func (c *salsa20Block) Encrypt(dst, src []byte) {
	panic(runtimeError)
}

func (c *salsa20Block) Decrypt(dst, src []byte) {
	panic(runtimeError)
}
