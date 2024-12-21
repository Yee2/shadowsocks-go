package associated

import (
	"shadowsocks/ciphers/core"
	"sync"
)

func New(cipher Cipher) core.TunnelProvider {
	return &aeadCipherProvider{cipher}
}

type aeadCipherProvider struct {
	Cipher
}

func (c *aeadCipherProvider) New(password string) core.Tunnel {
	t := &aead{
		key:       core.Kdf(password, c.KeySize()),
		KeySize:   c.KeySize(),
		SaltSize:  c.SaltSize(),
		NonceSize: c.NonceSize(),
		TagSize:   c.TagSize(),
		NewAEAD:   c.Cipher.New,
	}
	t.subKeyPool = &sync.Pool{New: func() interface{} {
		return make([]byte, t.KeySize)
	}}
	return t
}
