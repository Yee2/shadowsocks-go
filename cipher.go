package shadowsocks

import (
	"crypto/cipher"
	"crypto/md5"
	"errors"
)

var CipherNotSupported = errors.New("cipher not supported")
var AlreadyRegistered = errors.New("already registered")
var streamCiphers = make([]StreamCipher, 0)
var aeadCiphers = make([]AEADCipher, 0)

type StreamCipher interface {
	Name() string
	IVLength() int
	KeySize() int
	Cipher(key []byte) (cipher.Block, error)
	Decrypter(block cipher.Block, iv []byte) cipher.Stream
	Encrypter(block cipher.Block, iv []byte) cipher.Stream
}

// 注册一个 stream 加密方式
func RegisterStream(streamCipher StreamCipher) error {
	for i := range streamCiphers {
		if streamCipher == streamCiphers[i] || streamCiphers[i].Name() == streamCipher.Name() {
			return AlreadyRegistered
		}
	}
	streamCiphers = append(streamCiphers, streamCipher)
	return nil
}

// 注册一个 AEAD 加密方式
func RegisterAEAD(Cipher AEADCipher) error {
	for i := range aeadCiphers {
		if Cipher == aeadCiphers[i] || aeadCiphers[i].Name() == Cipher.Name() {
			return AlreadyRegistered
		}
	}
	aeadCiphers = append(aeadCiphers, Cipher)
	return nil
}

// 创建一个新的 shadowsocks 通道
func NewTunnel(method, password string) (Tunnel, error) {
	t, err := newTunnelStream(method, password)
	if err != nil && err != CipherNotSupported {
		return nil, err
	}
	if err == nil {
		return t, err
	}
	t, err = newTunnelAEAD(method, password)
	if err == nil {
		return t, err
	}
	if err != CipherNotSupported {
		return nil, err
	}
	return nil, CipherNotSupported
}

func newTunnelStream(method, password string) (Tunnel, error) {
	var cipher StreamCipher
	for i := range streamCiphers {
		if streamCiphers[i].Name() == method {
			cipher = streamCiphers[i]
		}
	}
	if cipher == nil {
		return nil, CipherNotSupported
	}
	key := kdf(password, cipher.KeySize())
	block, err := cipher.Cipher(key)
	if err != nil {
		return nil, err
	}
	return &stream{
		block:        block,
		IVLength:     cipher.IVLength(),
		NewDecrypter: cipher.Decrypter,
		NewEncrypter: cipher.Encrypter,
	}, nil
}

type AEADCipher interface {
	Name() string
	KeySize() int
	SaltSize() int
	NonceSize() int
	TagSize() int
	NewAEAD(key []byte) (cipher.AEAD, error)
}

func newTunnelAEAD(method, password string) (Tunnel, error) {
	var c AEADCipher
	for i := range aeadCiphers {
		if aeadCiphers[i].Name() == method {
			c = aeadCiphers[i]
		}
	}
	if c == nil {
		return nil, CipherNotSupported
	}
	key := kdf(password, c.KeySize())
	return &aead{
		key:       key,
		KeySize:   c.KeySize(),
		SaltSize:  c.SaltSize(),
		NonceSize: c.NonceSize(),
		TagSize:   c.TagSize(),
		NewAEAD:   c.NewAEAD,
	}, nil
}

// 获取支持的加密方式
func Supported() []string {
	list := make([]string, 0)
	for i := range streamCiphers {
		list = append(list, streamCiphers[i].Name())
	}
	for i := range aeadCiphers {
		list = append(list, aeadCiphers[i].Name())
	}
	return list
}

// from https://github.com/shadowsocks/go-shadowsocks2/blob/ef4b562095a69750509f82d3f82fc8e6dad50c6e/core/cipher.go
// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
