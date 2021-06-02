// Package ciphers
/**
container all encryption methods listed by shadowsocks.org but not show in blow.
to use those encryption methods you need import this package and ignore it sometime.
*/
package ciphers

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/Yee2/shadowsocks-go"
	"github.com/enceve/crypto/camellia"
	"golang.org/x/crypto/chacha20poly1305"
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	shadowsocks.Register(NewStream(&streamAES{"aes", 16, "cfb"}))
	shadowsocks.Register(NewStream(&streamAES{"aes", 24, "cfb"}))
	shadowsocks.Register(NewStream(&streamAES{"aes", 32, "cfb"}))
	shadowsocks.Register(NewStream(&streamAES{"aes", 16, "ctr"}))
	shadowsocks.Register(NewStream(&streamAES{"aes", 24, "ctr"}))
	shadowsocks.Register(NewStream(&streamAES{"aes", 32, "ctr"}))
	shadowsocks.Register(NewStream(&streamAES{"camellia", 16, "cfb"}))
	shadowsocks.Register(NewStream(&streamAES{"camellia", 24, "cfb"}))
	shadowsocks.Register(NewStream(&streamAES{"camellia", 32, "cfb"}))

	shadowsocks.Register(New(&aesgcm{keySize: 16, saltSize: 16}))
	shadowsocks.Register(New(&aesgcm{keySize: 24, saltSize: 24}))
	shadowsocks.Register(New(&aesgcm{keySize: 32, saltSize: 32}))
	shadowsocks.Register(New(&chacha20{}))
}

type streamAES struct {
	c       string
	keySize int
	mode    string
}

func (c *streamAES) Name() string {
	switch c.c {
	case "aes":
	case "camellia":
		if c.mode == "ctr" {
			panic("error")
		}
	default:
	}
	switch c.mode {
	case "cfb", "ctr":
	default:
		panic("error")
	}
	switch c.keySize {
	case 16, 24, 32:
	default:
		panic("error")
	}
	return fmt.Sprintf("%s-%d-%s", c.c, c.keySize*8, c.mode)
}

func (c *streamAES) IVLength() int {
	return 16
}

func (c *streamAES) KeySize() int {
	return c.keySize
}
func (c *streamAES) Cipher(key []byte) (cipher.Block, error) {
	switch c.c {
	case "aes":
		return aes.NewCipher(key)
	case "camellia":
		return camellia.NewCipher(key)
	default:
		panic("error")
	}
}
func (c *streamAES) Decryptor(block cipher.Block, iv []byte) cipher.Stream {
	switch c.mode {
	case "cfb":
		return cipher.NewCFBDecrypter(block, iv)
	case "ctr":
		return cipher.NewCTR(block, iv)
	default:
		panic("error")
	}
}
func (c *streamAES) Encryptor(block cipher.Block, iv []byte) cipher.Stream {
	switch c.mode {
	case "cfb":
		return cipher.NewCFBEncrypter(block, iv)
	case "ctr":
		return cipher.NewCTR(block, iv)
	default:
		panic("error")
	}
}

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
func (c *aesgcm) NewAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

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

func (*chacha20) NewAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}
