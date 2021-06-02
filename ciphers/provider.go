package ciphers

import (
	"github.com/Yee2/shadowsocks-go"
	"sync"
)

func New(cipher AEADCipher) shadowsocks.TunnelProvider {
	return &aeadCipherProvider{cipher}
}

func NewStream(cipher StreamCipher) shadowsocks.TunnelProvider {
	return &streamCipherProvider{cipher}
}

type aeadCipherProvider struct {
	AEADCipher
}

func (c *aeadCipherProvider) New(password string) shadowsocks.Tunnel {
	t := &aead{
		key:       kdf(password, c.KeySize()),
		KeySize:   c.KeySize(),
		SaltSize:  c.SaltSize(),
		NonceSize: c.NonceSize(),
		TagSize:   c.TagSize(),
		NewAEAD:   c.NewAEAD,
	}
	t.subKeyPool = &sync.Pool{New: func() interface{} {
		return make([]byte, t.KeySize)
	}}
	return t
}

type streamCipherProvider struct {
	StreamCipher
}

func (cipher *streamCipherProvider) New(password string) shadowsocks.Tunnel {
	key := kdf(password, cipher.KeySize())
	// TODO: check error
	block, _ := cipher.Cipher(key)
	return &stream{
		block:        block,
		IVLength:     cipher.IVLength(),
		NewDecryptor: cipher.Decryptor,
		NewEncryptor: cipher.Encryptor,
	}
}
