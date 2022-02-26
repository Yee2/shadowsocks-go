package stream

import (
	"crypto/cipher"
	"github.com/Yee2/shadowsocks-go/ciphers/core"
)

func NewStream(cipher Cipher) core.TunnelProvider {
	return &streamCipherProvider{cipher}
}

type Cipher interface {
	Name() string
	IVLength() int
	KeySize() int
	Cipher(key []byte) (cipher.Block, error)
	Decryptor(block cipher.Block, iv []byte) cipher.Stream
	Encryptor(block cipher.Block, iv []byte) cipher.Stream
}
type streamCipherProvider struct {
	Cipher
}

func (cipher *streamCipherProvider) New(password string) core.Tunnel {
	key := core.Kdf(password, cipher.KeySize())
	// TODO: check error
	block, _ := cipher.Cipher.Cipher(key)
	return &stream{
		block:        block,
		IVLength:     cipher.IVLength(),
		NewDecryptor: cipher.Decryptor,
		NewEncryptor: cipher.Encryptor,
	}
}
