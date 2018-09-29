/*
支持的方法:
 aes-128-cfb
 aes-192-cfb
 aes-256-cfb
 aes-128-ctr
 aes-192-ctr
 aes-256-ctr
 camellia-128-cfb
 camellia-192-cfb
 camellia-256-cfb
 aes-128-gcm
 aes-192-gcm
 aes-256-gcm
 chacha20-ietf-poly1305
 */
package shadowsocks

import (
	"fmt"
	"crypto/cipher"
	"crypto/aes"
	"github.com/enceve/crypto/camellia"
	"sync"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	once = &sync.Once{}
)

func init() {
	once.Do(func() {
		RegisterStream(&streamAES{"aes", 16, "cfb"})
		RegisterStream(&streamAES{"aes", 24, "cfb"})
		RegisterStream(&streamAES{"aes", 32, "cfb"})
		RegisterStream(&streamAES{"aes", 16, "ctr"})
		RegisterStream(&streamAES{"aes", 24, "ctr"})
		RegisterStream(&streamAES{"aes", 32, "ctr"})
		RegisterStream(&streamAES{"camellia", 16, "cfb"})
		RegisterStream(&streamAES{"camellia", 24, "cfb"})
		RegisterStream(&streamAES{"camellia", 32, "cfb"})

		RegisterAEAD(&aesgcm{keySize: 16, saltSize: 16})
		RegisterAEAD(&aesgcm{keySize: 24, saltSize: 24})
		RegisterAEAD(&aesgcm{keySize: 32, saltSize: 32})
		RegisterAEAD(&chacha20{})
	})
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
func (c *streamAES) Decrypter(block cipher.Block, iv []byte) cipher.Stream {
	switch c.mode {
	case "cfb":
		return cipher.NewCFBDecrypter(block, iv)
	case "ctr":
		return cipher.NewCTR(block, iv)
	default:
		panic("error")
	}
}
func (c *streamAES) Encrypter(block cipher.Block, iv []byte) cipher.Stream {
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
