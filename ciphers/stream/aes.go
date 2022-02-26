package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"github.com/enceve/crypto/camellia"
)

var AES128CFB = NewStream(&streamAES{"aes", 16, "cfb"})
var AES192CFB = NewStream(&streamAES{"aes", 24, "cfb"})
var AES256CFB = NewStream(&streamAES{"aes", 32, "cfb"})
var AES128CTR = NewStream(&streamAES{"aes", 16, "ctr"})
var AES192CTR = NewStream(&streamAES{"aes", 24, "ctr"})
var AES256CTR = NewStream(&streamAES{"aes", 32, "ctr"})

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
