package shadowsocks

import (
	"crypto/cipher"
	"errors"
	"io"
	"crypto/md5"
)

var CipherNotSupported = errors.New("cipher not supported")
var AlreadyRegistered = errors.New("already registered")
var StreamCiphers = make([]StreamCipher, 0)
var AEADCiphers = make([]AEADCipher, 0)

type StreamCipher interface {
	Name() string
	//Alias() []string
	IVLength() int
	KeySize() int
	Cipher(key []byte) (cipher.Block, error)
	Decrypter(block cipher.Block, iv []byte) cipher.Stream
	Encrypter(block cipher.Block, iv []byte) cipher.Stream
}

// 注册一个 stram 加密方式
func RegisterStream(streamCipher StreamCipher) error {
	for i := range StreamCiphers {
		if streamCipher == StreamCiphers[i] || StreamCiphers[i].Name() == streamCipher.Name() {
			return AlreadyRegistered
		}
	}
	StreamCiphers = append(StreamCiphers, streamCipher)
	return nil
}

// 注册一个 AEAD 加密方式
func RegisterAEAD(Cipher AEADCipher) error {
	for i := range AEADCiphers {
		if Cipher == AEADCiphers[i] || AEADCiphers[i].Name() == Cipher.Name() {
			return AlreadyRegistered
		}
	}
	AEADCiphers = append(AEADCiphers, Cipher)
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
	if err != nil && err != CipherNotSupported {
		return nil, err
	}
	return nil, CipherNotSupported
}

func newTunnelStream(method, password string) (Tunnel, error) {
	var cipher StreamCipher
	for i := range StreamCiphers {
		if StreamCiphers[i].Name() == method {
			cipher = StreamCiphers[i]
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
	for i := range AEADCiphers {
		if AEADCiphers[i].Name() == method {
			c = AEADCiphers[i]
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
	list := make([]string,0)
	for i := range StreamCiphers{
		list=append(list,StreamCiphers[i].Name())
	}
	for i := range AEADCiphers{
		list=append(list,AEADCiphers[i].Name())
	}
	return list
}

func GetIV(reader io.Reader, size int) ([]byte, error) {
	bs := make([]byte, size)
	_, err := io.ReadFull(reader, bs)
	if err != nil {
		return []byte{}, err
	}
	return bs, nil
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
